package syslog

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
)

// Listener is the runnable half of the syslog connector (Phase F5 hardening): a UDP socket
// that receives datagrams, parses each, and hands the structured message to a sink. It
// turns the pure parser into a running connector. UDP:514 is the standard port, but the
// address is configurable so it can run unprivileged on a high port (the privileged bind /
// transparent redirect is a deployment concern, as with the other connectors).
//
// A datagram that does not parse is COUNTED and dropped, not fatal — one malformed packet
// from one noisy source must never stop ingest (an ingest that dies on bad input is a
// denial-of-service waiting to happen). The drop count is observable so a flood of
// unparseable input is visible, not silent (D28).
type Listener struct {
	conn    *net.UDPConn
	sink    func(Message)
	logger  *slog.Logger
	dropped atomic.Int64 // datagrams that failed to parse (read via Dropped)
}

// Listen binds a UDP socket at addr and delivers each parsed message to sink. It returns
// the Listener (so the caller can read its address and stats) without blocking; call Serve
// to run the receive loop.
func Listen(addr string, sink func(Message), logger *slog.Logger) (*Listener, error) {
	if sink == nil {
		return nil, fmt.Errorf("syslog: nil sink")
	}
	if logger == nil {
		logger = slog.Default()
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("syslog: resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("syslog: listen %q: %w", addr, err)
	}
	return &Listener{conn: conn, sink: sink, logger: logger}, nil
}

// Addr is the bound address (useful when the caller passed :0 for an ephemeral port).
func (l *Listener) Addr() *net.UDPAddr { return l.conn.LocalAddr().(*net.UDPAddr) }

// Dropped reports how many datagrams failed to parse.
func (l *Listener) Dropped() int64 { return l.dropped.Load() }

// Serve runs the receive loop until ctx is cancelled, then closes the socket. Each datagram
// is parsed; a parse failure increments the drop count and is skipped. One buffer sized to
// the line bound is reused — a datagram larger than the bound is truncated by the kernel,
// which the parser then rejects (a too-long "line" is not a valid syslog message).
func (l *Listener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = l.conn.Close() // unblocks ReadFromUDP with an error
	}()

	buf := make([]byte, maxLine)
	for {
		n, _, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("syslog: read: %w", err)
		}
		msg, perr := Parse(buf[:n])
		if perr != nil {
			l.dropped.Add(1)
			continue
		}
		l.sink(msg)
	}
}
