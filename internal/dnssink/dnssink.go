// Package dnssink is the preventive DNS resolver (NIPS-8): it turns DNS from a passive tap into an
// inline control. It reads UDP queries, SINKHOLES a policy/IOC-blocked domain (answers NXDOMAIN so the
// client cannot resolve the malicious name — RPZ-style), and FORWARDS every other query to a configured
// upstream, relaying the response.
//
// Fail-open is the safety invariant (D73/D17): the resolver forwards a query UNLESS it is certain the
// domain is blocked — a message it cannot parse, or a domain the block set does not match, is forwarded,
// never dropped or NXDOMAIN'd. A resolver that blackholed on uncertainty would break name resolution for
// the whole fleet, which is far worse than missing one sinkhole.
package dnssink

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/dns"
)

// defaultTimeout bounds a forward to the upstream so a slow upstream cannot wedge a handler.
const defaultTimeout = 3 * time.Second

// maxMsg bounds a read/relayed DNS message (512 classic, up to 4096 with EDNS0).
const maxMsg = 4096

// Resolver forwards DNS queries to an upstream and sinkholes a blocked domain.
type Resolver struct {
	Upstream string                 // "ip:port" of the real resolver to forward to
	Blocked  func(name string) bool // reports whether a queried domain is blocked (IOC-feed-backed in prod)
	Timeout  time.Duration          // per-forward timeout; 0 → defaultTimeout
	Log      *slog.Logger
}

func (r Resolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}

// Serve reads queries from pc until ctx is done, handling each in its own goroutine.
func (r Resolver) Serve(ctx context.Context, pc net.PacketConn) error {
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, maxMsg)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go r.handle(query, client, pc)
	}
}

// handle decides one query: sinkhole a blocked domain, else forward. Fail-open — anything not certainly
// blocked is forwarded.
func (r Resolver) handle(query []byte, client net.Addr, pc net.PacketConn) {
	q, err := dns.ParseQuery(query)
	if err != nil {
		// Cannot classify → forward (fail-open). Never drop or sinkhole on a parse failure.
		r.forward(query, client, pc)
		return
	}
	if r.Blocked != nil && r.Blocked(q.Name) {
		resp := nxdomain(query)
		if resp == nil {
			r.forward(query, client, pc) // malformed to build a response → fail-open forward
			return
		}
		_, _ = pc.WriteTo(resp, client)
		if r.Log != nil {
			r.Log.Info("dnssink: sinkholed a blocked domain (NXDOMAIN)", slog.String("name", q.Name))
		}
		return
	}
	r.forward(query, client, pc)
}

// forward relays the query to the upstream and writes the response back to the client. An upstream error
// leaves the query unanswered (a normal resolver outcome when the upstream is down) — it is NOT a
// sinkhole and MUST NOT be turned into one.
func (r Resolver) forward(query []byte, client net.Addr, pc net.PacketConn) {
	uc, err := net.DialTimeout("udp", r.Upstream, r.timeout())
	if err != nil {
		if r.Log != nil {
			r.Log.Warn("dnssink: upstream dial failed (query unanswered, NOT sinkholed)", slog.String("err", err.Error()))
		}
		return
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(r.timeout()))
	if _, err := uc.Write(query); err != nil {
		return
	}
	resp := make([]byte, maxMsg)
	m, err := uc.Read(resp)
	if err != nil {
		if r.Log != nil {
			r.Log.Warn("dnssink: upstream read failed", slog.String("err", err.Error()))
		}
		return
	}
	_, _ = pc.WriteTo(resp[:m], client)
}

// nxdomain builds an NXDOMAIN response from a query: the same transaction id and question, QR=1,
// RA=1, RCODE=3 (NXDOMAIN), and zero answer/authority/additional records. Returns nil if the query is
// too short to carry a header+question (the caller then fails open by forwarding).
func nxdomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	// Find the end of the question section: header (12) + QNAME + QTYPE(2) + QCLASS(2).
	off := 12
	for {
		if off >= len(query) {
			return nil // truncated name
		}
		l := int(query[off])
		if l == 0 {
			off++ // consume the root label
			break
		}
		if l&0xc0 != 0 {
			return nil // a pointer in a QNAME is malformed
		}
		off += l + 1
	}
	off += 4 // QTYPE + QCLASS
	if off > len(query) {
		return nil
	}
	resp := make([]byte, off)
	copy(resp, query[:off])
	// Flags: QR=1, keep Opcode + RD from the query, set RA=1, RCODE=3.
	resp[2] = (query[2] & 0x7a) | 0x80 // QR=1, preserve Opcode(bits 3-6) + RD(bit0); clear AA/TC
	resp[3] = 0x83                     // RA=1 (0x80) + RCODE=3 (NXDOMAIN)
	// Counts: QDCOUNT unchanged (echoing the one question), AN/NS/AR = 0.
	resp[6], resp[7] = 0, 0   // ANCOUNT
	resp[8], resp[9] = 0, 0   // NSCOUNT
	resp[10], resp[11] = 0, 0 // ARCOUNT
	return resp
}
