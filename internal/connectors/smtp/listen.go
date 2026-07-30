package smtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// defaultMaxConns caps concurrent sessions so a connection flood cannot spawn unbounded
	// goroutines/buffers. Excess connections are refused (closed + counted), not queued.
	defaultMaxConns = 128
	// defaultIdleTimeout bounds how long a session may stall between lines, defeating slowloris —
	// a client that opens a connection and dribbles (or sends nothing) is dropped, not held.
	defaultIdleTimeout = 30 * time.Second
)

// Listener is the runnable half of the SMTP connector (NIPS-3): a minimal SMTP server that
// accepts a session, drives the client through the dialogue enough to receive the message,
// then parses the captured transcript (D102) and hands the message to a sink — turning the
// pure parser into a running connector for email DLP. Port 25/587 is standard; the address
// is configurable so it runs unprivileged on a high port (the privileged bind / MTA
// interception is a deployment concern, as with the other connectors).
//
// It responds just enough for a real client to complete a session (220/250/354/221); it does
// NOT relay the mail — it is a capture/monitoring endpoint. A session that fails to parse is
// COUNTED and refused, never fatal to the listener (D17/D28).
type Listener struct {
	ln      net.Listener
	sink    func(*Message)
	logger  *slog.Logger
	dropped atomic.Int64
	refused atomic.Int64

	// MaxBody caps the bytes buffered for ONE session (the anti-OOM ceiling for a no-newline
	// flood); MaxConns caps concurrent sessions; IdleTimeout bounds per-line stall. All fall back
	// to their defaults when non-positive, so a caller may tune them before Serve but never disable
	// the protection. Exported so a test can set aggressive bounds and drive each guard directly.
	MaxBody     int64
	MaxConns    int
	IdleTimeout time.Duration
	sem         chan struct{}

	// Decide turns this from a CAPTURE endpoint into a FILTERING one (NIPS: "SMTP is captured and
	// inspected, not filtered" was the named gap). It is called at end-of-DATA — the only moment SMTP
	// offers to refuse a message — and returning true rejects it with a 5xx instead of accepting it.
	//
	// NIL IS THE DEFAULT AND CHANGES NOTHING (D1, observe-only): every existing deployment keeps
	// capturing and accepting exactly as before. Filtering is opt-in, like every other enforcer.
	//
	// It REPLACES the sink for that message rather than running alongside it. The engine's implementation
	// runs the full pipeline synchronously to reach a verdict, and calling the sink as well would put the
	// same message through classify → policy → audit twice — one message, two ledger entries, two alerts.
	//
	// FAIL-OPEN IS THE CALLER'S JOB, and it is stated here because the failure is silent otherwise: an
	// implementation that returns true on its own internal error would block mail because the classifier
	// was down, which is how a DLP product takes out a mail server. D17/D18 — the engine's hook returns
	// false when the pipeline errors, and bounds itself with a deadline.
	Decide func(*Message) bool
	// rejected counts messages refused by Decide.
	rejected atomic.Int64
}

// Rejected reports how many messages were REFUSED at end-of-DATA. Zero when no Decide hook is
// configured, which is the observe-only default.
func (l *Listener) Rejected() int64 { return l.rejected.Load() }

// Listen binds a TCP socket at addr and delivers each parsed message to sink.
func Listen(addr string, sink func(*Message), logger *slog.Logger) (*Listener, error) {
	if sink == nil {
		return nil, fmt.Errorf("smtp: nil sink")
	}
	if logger == nil {
		logger = slog.Default()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp: listen %q: %w", addr, err)
	}
	return &Listener{ln: ln, sink: sink, logger: logger, MaxBody: maxMessage,
		MaxConns: defaultMaxConns, IdleTimeout: defaultIdleTimeout}, nil
}

// Addr is the bound address (useful when the caller passed :0 for an ephemeral port).
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Dropped reports how many sessions failed to parse.
func (l *Listener) Dropped() int64 { return l.dropped.Load() }

// Refused reports how many connections were closed unhandled because the concurrency cap was full.
func (l *Listener) Refused() int64 { return l.refused.Load() }

// Serve accepts sessions until ctx is cancelled. Each session runs in its own goroutine, but the
// number of concurrent sessions is CAPPED: a connection arriving while the cap is full is refused
// (closed + counted) rather than queued, so a connection flood cannot grow goroutines/buffers
// without bound.
func (l *Listener) Serve(ctx context.Context) error {
	max := l.MaxConns
	if max <= 0 {
		max = defaultMaxConns
	}
	l.sem = make(chan struct{}, max)
	go func() { <-ctx.Done(); _ = l.ln.Close() }()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("smtp: accept: %w", err)
		}
		select {
		case l.sem <- struct{}{}:
			go func() { defer func() { <-l.sem }(); l.handle(conn) }()
		default:
			// At capacity — refuse this connection rather than let it accumulate.
			l.refused.Add(1)
			_ = conn.Close()
		}
	}
}

// handle runs one SMTP session: it replies to the dialogue and accumulates the client's
// command lines into a transcript, then parses it on QUIT/close and delivers the message.
func (l *Listener) handle(conn net.Conn) {
	defer conn.Close()
	// RECOVER from any panic parsing a crafted session (ENG-2): a panic in one session's parsing
	// must be contained (dropped + counted), never crash the engine that hosts this listener.
	defer func() {
		if r := recover(); r != nil {
			l.dropped.Add(1)
			l.logger.Error("smtp: recovered from panic handling a session", "panic", r)
		}
	}()
	idle := l.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	maxBody := l.MaxBody
	if maxBody <= 0 {
		maxBody = maxMessage
	}
	w := func(s string) { _, _ = conn.Write([]byte(s)) }
	w("220 openshield.capture ESMTP\r\n")

	var transcript strings.Builder
	// Bound the TOTAL bytes the session can make us buffer: without this, a stream with no newline
	// makes ReadString grow its buffer unbounded (OOM). The LimitReader caps it at maxBody, so an
	// unterminated flood returns EOF at the ceiling instead of exhausting memory.
	r := bufio.NewReader(io.LimitReader(conn, maxBody+1))
	inData := false
	// decided is set once a Decide hook has handled the message at end-of-DATA, so the delivery at QUIT
	// (or connection close) does not put the SAME message through the pipeline a second time.
	decided := false
	var total int64
	for {
		// Per-line idle deadline (slowloris defense): a client that stalls between lines is dropped
		// rather than holding a goroutine + connection indefinitely. Each line resets it, so a slow
		// but progressing client is fine.
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		line, err := r.ReadString('\n')
		if err != nil {
			break // client closed, timed out, or hit the size ceiling — parse what we have
		}
		total += int64(len(line))
		if total > maxBody {
			w("552 message too large\r\n")
			return
		}
		transcript.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")

		if inData {
			if trimmed == "." {
				inData = false
				// THE ONLY MOMENT SMTP OFFERS TO REFUSE A MESSAGE. After this reply the client
				// considers it accepted, so a verdict reached later can report but cannot prevent.
				if l.Decide != nil {
					decided = true
					if m, perr := ParseSession([]byte(transcript.String())); perr != nil {
						// Unparseable: counted and ACCEPTED, never refused. Refusing what we failed to
						// understand would make a parser bug look like a policy decision to the sender.
						l.dropped.Add(1)
						w("250 2.0.0 queued\r\n")
					} else if l.Decide(m) {
						l.rejected.Add(1)
						// 550 5.7.1 is the policy refusal: permanent, so a conforming sender does not
						// retry the same content forever, and distinguishable from a 4xx capacity issue.
						w("550 5.7.1 message refused by policy\r\n")
					} else {
						w("250 2.0.0 queued\r\n")
					}
				} else {
					w("250 2.0.0 queued\r\n")
				}
			}
			continue
		}
		switch upper := strings.ToUpper(trimmed); {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			w("250 openshield.capture\r\n")
		case strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"), upper == "RSET":
			w("250 2.1.0 ok\r\n")
		case upper == "DATA":
			inData = true
			w("354 end data with <CRLF>.<CRLF>\r\n")
		case upper == "QUIT":
			w("221 2.0.0 bye\r\n")
			if !decided {
				l.deliver(transcript.String())
			}
			return
		default:
			w("250 2.0.0 ok\r\n")
		}
	}
	if !decided {
		l.deliver(transcript.String())
	}
}

// deliver parses the captured transcript and hands the message to the sink; a session that
// does not parse (no sender/recipient, unterminated DATA) is dropped and counted.
func (l *Listener) deliver(transcript string) {
	m, err := ParseSession([]byte(transcript))
	if err != nil {
		l.dropped.Add(1)
		return
	}
	l.sink(m)
}
