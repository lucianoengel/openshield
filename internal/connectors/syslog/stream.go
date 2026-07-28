package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/limiter"
)

// StreamListener receives syslog over a STREAM transport — TCP, or TLS when a config is supplied
// (D337). It exists because the datagram listener cannot be made to lose events visibly.
//
// WHAT UDP CANNOT DO, and why this is not a preference. A datagram the kernel discards for want of
// receive buffer never reaches the application, so no counter the application keeps can observe it:
// `Dropped` counts messages that FAILED TO PARSE, which is a different and much less dangerous thing.
// The result is the silent gap the product forbids everywhere else — nobody can tell "that device sent
// nothing" from "we could not read what it sent" (D31). A stream gives delivery to the receiver and, more
// importantly, BACKPRESSURE: a receiver that cannot keep up slows its senders instead of discarding.
//
// WHAT IT STILL DOES NOT DO, stated here because the honest claim is narrower than "no loss": there is no
// application-level acknowledgement of PERSISTENCE. A sender whose write returns has reached this
// process's socket, not the database, and a process killed with buffered data loses it. The claim is that
// loss now requires a crash or an explicit refusal — both observable — rather than a buffer quietly
// filling.
type StreamListener struct {
	ln     net.Listener
	sink   func(Message)
	logger *slog.Logger

	dropped     atomic.Int64 // messages that failed to parse
	oversize    atomic.Int64 // messages refused for exceeding maxLine
	rateLimited atomic.Int64
	accepted    atomic.Int64

	// Limiter bounds admission (NIPS-7), as for datagrams: an accepted message can mint a pipeline
	// event and a ledger write, so a flood must be capped at the door.
	Limiter *limiter.Limiter
	// MaxConns bounds concurrent connections. A stream listener holds resources a datagram one does
	// not, so the cap is part of the transport rather than an afterthought.
	MaxConns int
	// IdleTimeout closes a connection that sends nothing, so an abandoned socket is not held forever.
	IdleTimeout time.Duration
}

const (
	defaultMaxConns    = 256
	defaultIdleTimeout = 5 * time.Minute
)

// ListenStream binds a stream socket at addr. A non-nil tlsConf makes it TLS; the caller supplies one
// that REQUIRES a client certificate, because an unauthenticated sender can inject events into a store
// operators are invited to treat as evidence, and fabricated evidence is worse than missing evidence.
func ListenStream(addr string, sink func(Message), tlsConf *tls.Config, logger *slog.Logger) (*StreamListener, error) {
	if sink == nil {
		return nil, fmt.Errorf("syslog: nil sink")
	}
	if logger == nil {
		logger = slog.Default()
	}
	var ln net.Listener
	var err error
	if tlsConf != nil {
		ln, err = tls.Listen("tcp", addr, tlsConf)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("syslog: listen %q: %w", addr, err)
	}
	return &StreamListener{
		ln: ln, sink: sink, logger: logger,
		Limiter:     limiter.New(defaultRatePerSec, defaultBurst),
		MaxConns:    defaultMaxConns,
		IdleTimeout: defaultIdleTimeout,
	}, nil
}

// Addr is the bound address (useful when the caller passed :0).
func (l *StreamListener) Addr() net.Addr { return l.ln.Addr() }

// Dropped reports messages that failed to parse.
func (l *StreamListener) Dropped() int64 { return l.dropped.Load() }

// Oversize reports messages REFUSED for exceeding the line bound.
//
// Separate from Dropped on purpose. Over a datagram the kernel truncates before the application has a
// say, and the result surfaces as a mystery parse failure; over a stream the receiver can say no, so an
// over-bound message is reported as what it is. "Sender X sent 9KB against an 8KB bound" is actionable;
// "a line did not parse" is not.
func (l *StreamListener) Oversize() int64 { return l.oversize.Load() }

// RateLimited reports messages refused by the admission limiter.
func (l *StreamListener) RateLimited() int64 { return l.rateLimited.Load() }

// Accepted reports connections accepted.
func (l *StreamListener) Accepted() int64 { return l.accepted.Load() }

// Serve accepts connections until ctx is done.
func (l *StreamListener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = l.ln.Close() // unblocks Accept
	}()

	sem := make(chan struct{}, l.MaxConns)
	var wg sync.WaitGroup
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			// A single failed handshake or a reset is not fatal: one bad sender must never stop ingest
			// for the estate, which is the same rule the datagram path follows for a bad packet.
			l.logger.Warn("syslog: accept failed", slog.String("err", err.Error()))
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			// At the cap. Refusing LOUDLY beats queueing forever: the sender sees a closed connection
			// and retries, which is the backpressure this transport exists to provide.
			l.logger.Warn("syslog: connection cap reached — refusing", slog.Int("max", l.MaxConns))
			_ = conn.Close()
			continue
		}
		l.accepted.Add(1)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			l.handle(ctx, c)
		}(conn)
	}
}

// handle reads framed messages from one connection until it closes.
func (l *StreamListener) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 64<<10)
	for {
		if ctx.Err() != nil {
			return
		}
		if l.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(l.IdleTimeout))
		}
		line, err := l.readFrame(br)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				l.logger.Debug("syslog: stream read ended", slog.String("err", err.Error()))
			}
			return
		}
		if len(line) == 0 {
			continue
		}
		if l.Limiter != nil && !l.Limiter.Allow() {
			l.rateLimited.Add(1)
			continue
		}
		m, perr := Parse(line)
		if perr != nil {
			// COUNTED, and the connection SURVIVES it. A parse error that closed the stream would let
			// one malformed message from one device stop the whole estate's feed — a far worse outcome
			// than the message itself.
			l.dropped.Add(1)
			continue
		}
		l.sink(m)
	}
}

// readFrame reads one message using either RFC 6587 framing.
//
// BOTH, detected per message, because real senders use both — rsyslog defaults to one and many
// appliances to the other, and requiring a single framing is how a log source ends up not onboarded at
// all. An un-ingested source produces no alerts and looks exactly like a quiet one.
//
// A message beginning with a digit followed by a space is octet-counted (`MSG-LEN SP MSG`); anything
// else is read to the newline. Deciding per message rather than per connection means a sender that mixes
// them still works.
func (l *StreamListener) readFrame(br *bufio.Reader) ([]byte, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] >= '0' && first[0] <= '9' {
		return l.readOctetCounted(br)
	}
	return l.readLineFrame(br)
}

// readOctetCounted reads `MSG-LEN SP MSG`.
func (l *StreamListener) readOctetCounted(br *bufio.Reader) ([]byte, error) {
	digits, err := br.ReadString(' ')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(digits[:len(digits)-1])
	if err != nil || n < 0 {
		// NOT an error that ends the stream. RFC 6587 framing is auto-detected, and the detection is
		// inherently ambiguous: a newline-framed message that merely BEGINS with a digit ("2026-07-28
		// disk full") looks like an octet count until the number fails to parse. Killing the connection
		// there would let one such message stop a device's whole feed — the failure the per-message
		// parse-and-continue rule exists to prevent. So it is counted and the rest of the line is
		// skipped, leaving the stream at a message boundary.
		l.dropped.Add(1)
		if _, derr := br.ReadString('\n'); derr != nil {
			return nil, derr
		}
		return nil, nil
	}
	if n > maxLine {
		// REFUSED, not truncated — and the count is discarded from the stream so the connection stays
		// in sync rather than reading the oversized body as if it were the next message.
		l.oversize.Add(1)
		l.logger.Warn("syslog: message exceeds the line bound — refused",
			slog.Int("bytes", n), slog.Int("max", maxLine))
		if _, derr := br.Discard(n); derr != nil {
			return nil, derr
		}
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readLineFrame reads an LF-terminated message, refusing one that exceeds the bound.
func (l *StreamListener) readLineFrame(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxLine {
			// Drain the rest of the over-bound line so the next read starts at a message boundary.
			for isPrefix {
				_, isPrefix, err = br.ReadLine()
				if err != nil {
					return nil, err
				}
			}
			l.oversize.Add(1)
			l.logger.Warn("syslog: message exceeds the line bound — refused",
				slog.Int("bytes", len(out)), slog.Int("max", maxLine))
			return nil, nil
		}
		if !isPrefix {
			return out, nil
		}
	}
}
