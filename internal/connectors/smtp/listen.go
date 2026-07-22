package smtp

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
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
	maxBody int64
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
	return &Listener{ln: ln, sink: sink, logger: logger, maxBody: maxMessage}, nil
}

// Addr is the bound address (useful when the caller passed :0 for an ephemeral port).
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Dropped reports how many sessions failed to parse.
func (l *Listener) Dropped() int64 { return l.dropped.Load() }

// Serve accepts sessions until ctx is cancelled, each handled in its own goroutine.
func (l *Listener) Serve(ctx context.Context) error {
	go func() { <-ctx.Done(); _ = l.ln.Close() }()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("smtp: accept: %w", err)
		}
		go l.handle(conn)
	}
}

// handle runs one SMTP session: it replies to the dialogue and accumulates the client's
// command lines into a transcript, then parses it on QUIT/close and delivers the message.
func (l *Listener) handle(conn net.Conn) {
	defer conn.Close()
	w := func(s string) { _, _ = conn.Write([]byte(s)) }
	w("220 openshield.capture ESMTP\r\n")

	var transcript strings.Builder
	r := bufio.NewReader(conn)
	inData := false
	var total int64
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break // client closed (or read error) — parse what we have
		}
		total += int64(len(line))
		if total > l.maxBody {
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
