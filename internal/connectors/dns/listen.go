package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/lucianoengel/openshield/internal/connectors/limiter"
)

const (
	// defaultRatePerSec / defaultBurst bound how fast the listener admits datagrams into the
	// pipeline (NIPS-7). Each admitted query mints a ledger write, so a spoofed-source flood would
	// grow the audit ledger at wire speed; a global token bucket caps that. Generous enough for
	// real resolution monitoring, low enough that a flood is bounded — tunable via Limiter.
	defaultRatePerSec = 2000
	defaultBurst      = 4000
)

// Listener is the runnable half of the DNS connector (NIPS-3): a UDP socket that receives
// DNS query datagrams, parses each, and hands the parsed query to a sink — turning the pure
// parser (D101) into a running connector that can see live resolution. UDP:53 is the
// standard port; the address is configurable so it runs unprivileged on a high port (the
// privileged bind / transparent redirect that steers traffic to it is a deployment concern,
// as with the other connectors).
//
// A datagram that does not parse (not a query, malformed) is DROPPED and COUNTED, never
// fatal — one bad packet from one host must not stop resolution monitoring (D17). The drop
// count is observable (D28), so a flood of unparseable input is visible, not silent.
type Listener struct {
	conn        *net.UDPConn
	sink        func(srcIP string, q Query)
	logger      *slog.Logger
	dropped     atomic.Int64
	rateLimited atomic.Int64
	// Limiter bounds the rate at which datagrams are admitted to the pipeline (NIPS-7); a flood
	// beyond it is rate-dropped (counted), so the audit-ledger write rate is capped. Defaults on;
	// set to nil before Serve to disable, or replace to tune.
	Limiter *limiter.Limiter
}

// Listen binds a UDP socket at addr and delivers each parsed query — with the datagram's
// source IP — to sink. The source IP is load-bearing: a DNS query's Event carries it as the
// flow's origin (a network decision that could not say WHO asked is not actionable).
func Listen(addr string, sink func(srcIP string, q Query), logger *slog.Logger) (*Listener, error) {
	if sink == nil {
		return nil, fmt.Errorf("dns: nil sink")
	}
	if logger == nil {
		logger = slog.Default()
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns: resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("dns: listen %q: %w", addr, err)
	}
	return &Listener{conn: conn, sink: sink, logger: logger,
		Limiter: limiter.New(defaultRatePerSec, defaultBurst)}, nil
}

// Addr is the bound address (useful when the caller passed :0 for an ephemeral port).
func (l *Listener) Addr() *net.UDPAddr { return l.conn.LocalAddr().(*net.UDPAddr) }

// RateLimited reports how many datagrams were dropped by the admission rate limit (NIPS-7).
func (l *Listener) RateLimited() int64 { return l.rateLimited.Load() }

// Dropped reports how many datagrams failed to parse.
func (l *Listener) Dropped() int64 { return l.dropped.Load() }

// Serve runs the receive loop until ctx is cancelled, then closes the socket. A DNS message
// fits comfortably in 512 bytes (or 4 KB with EDNS); the buffer is sized for that, and a
// larger datagram is truncated by the kernel, which the parser then rejects.
func (l *Listener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = l.conn.Close() // unblocks ReadFromUDP
	}()

	buf := make([]byte, 4096)
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("dns: read: %w", err)
		}
		// Admission rate limit (NIPS-7): beyond the sustained rate, drop the datagram BEFORE it
		// mints a pipeline event + ledger write, so a spoofed-source flood cannot grow the ledger
		// at wire speed. Counted separately so a flood is observable, not silent (D28).
		if l.Limiter != nil && !l.Limiter.Allow() {
			l.rateLimited.Add(1)
			continue
		}
		srcIP := ""
		if addr != nil {
			srcIP = addr.IP.String()
		}
		l.handleDatagram(buf[:n], srcIP)
	}
}

// handleDatagram parses one datagram and delivers it, RECOVERING from any panic (ENG-2): the engine
// now parses attacker-controlled wire bytes IN-PROCESS, so a panic in the parser or the sink on a
// crafted datagram must be contained to that datagram (dropped + counted), never crash the engine.
func (l *Listener) handleDatagram(datagram []byte, srcIP string) {
	defer func() {
		if r := recover(); r != nil {
			l.dropped.Add(1)
			l.logger.Error("dns: recovered from panic handling a datagram", "panic", r)
		}
	}()
	q, perr := ParseQuery(datagram)
	if perr != nil {
		l.dropped.Add(1)
		return
	}
	l.sink(srcIP, q)
}
