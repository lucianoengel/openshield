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
}

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
				w("250 2.0.0 queued\r\n")
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
			l.deliver(transcript.String())
			return
		default:
			w("250 2.0.0 ok\r\n")
		}
	}
	l.deliver(transcript.String())
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
