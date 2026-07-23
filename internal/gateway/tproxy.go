package gateway

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// maxPeek bounds how many initial flow bytes are buffered to recover the SNI (a ClientHello is
// well under this); peekDeadline bounds how long we wait for the client to speak first, so a
// server-speaks-first or slow flow fails open promptly.
const (
	maxPeek      = 4096
	peekDeadline = 500 * time.Millisecond
)

// FlowHint carries what was peeked from a flow's initial bytes for the decision: the TLS SNI
// hostname ("" when not recoverable) and the raw peeked payload. The payload is handed to the
// sandboxed content-signature engine (NIPS-2) so a malicious cleartext payload is dropped inline;
// for a TLS flow it is the ClientHello (a handshake), which matches no content signature.
type FlowHint struct {
	SNI     string
	Payload []byte
}

// Transparent (TPROXY) inline data-plane (NIPS-1): the gateway can act as an inline network
// IPS, not only an explicit HTTP proxy. A TPROXY nftables/iptables rule redirects a TCP flow
// to a transparent listener (ListenTransparent, linux); each accepted connection's LocalAddr
// is the ORIGINAL destination the client meant to reach (TPROXY preserves it). The flow is
// decided through the pipeline on its metadata and either DROPPED (a real inline block at L4)
// or SPLICED bidirectionally to its original destination.
//
// Egress fail-open is load-bearing (ADR-8/D73/D17): a pipeline error forwards the flow rather
// than dropping it — inline prevention degrades to a passive wire, never a network outage.

// DecideFunc decides a flow on its metadata plus a peeked hint (the SNI): block reports whether to
// drop the flow. An error is a DETECTION failure and MUST be treated as allow by the caller
// (fail-open).
type DecideFunc func(ctx context.Context, origDst, src net.Addr, hint FlowHint) (block bool, err error)

// DialFunc connects to a flow's original destination (production: a net.Dialer).
type DialFunc func(origDst net.Addr) (net.Conn, error)

// handleFlow decides one intercepted flow and either drops it or splices it to its original
// destination. It always closes the client connection when it returns.
//
// Fail-open: a decide ERROR is treated as allow (splice) — a detection failure must not break
// egress. A dial failure (the real destination is down) simply ends the flow; it is not a
// policy block.
func handleFlow(ctx context.Context, client net.Conn, origDst net.Addr, decide DecideFunc, dial DialFunc, log *slog.Logger) {
	defer client.Close()

	// Peek the initial bytes to recover the SNI, without consuming them (they are replayed to the
	// upstream on splice, so an allowed flow is byte-for-byte transparent). A peek timeout/error
	// yields no bytes and no SNI — the flow then decides on metadata and splices (fail-open).
	peeked := peekInitial(client)
	hint := FlowHint{SNI: extractSNI(peeked), Payload: peeked}

	block, err := decide(ctx, origDst, client.RemoteAddr(), hint)
	if err != nil {
		// Fail-open: forward the flow, audit the failure. Never drop on a detection error.
		if log != nil {
			log.Warn("tproxy: pipeline error — forwarding flow (fail-open)", "dst", origDst.String(), "err", err.Error())
		}
		block = false
	}
	if block {
		// Drop: closing the client (via defer) refuses the flow. No upstream dial, no bytes.
		if log != nil {
			log.Info("tproxy: flow dropped by policy", "dst", origDst.String(), "sni", hint.SNI, "src", client.RemoteAddr().String())
		}
		return
	}

	upstream, derr := dial(origDst)
	if derr != nil {
		if log != nil {
			log.Warn("tproxy: dial original destination failed", "dst", origDst.String(), "err", derr.Error())
		}
		return
	}
	defer upstream.Close()
	// Replay the peeked bytes first so the upstream sees the original handshake, then splice.
	spliceWithPrefix(client, upstream, peeked)
}

// peekInitial reads up to maxPeek bytes from the client under a short deadline, returning what it
// read (possibly empty). It does not consume from the caller's view: the returned bytes are
// replayed to the upstream. A read error or timeout returns whatever was read (often nothing) so
// the flow fails open on the peek.
func peekInitial(client net.Conn) []byte {
	_ = client.SetReadDeadline(time.Now().Add(peekDeadline))
	buf := make([]byte, maxPeek)
	n, _ := client.Read(buf)
	_ = client.SetReadDeadline(time.Time{}) // clear the deadline for the splice
	return buf[:n]
}

// spliceWithPrefix copies bytes bidirectionally between the client and the upstream, sending the
// peeked prefix to the upstream FIRST (so it sees the original handshake) then the rest of the
// client stream. When one direction ends it closes both connections to unblock the other, then
// waits for both copies to finish.
func spliceWithPrefix(client, upstream net.Conn, prefix []byte) {
	done := make(chan struct{}, 2)
	go func() {
		if len(prefix) > 0 {
			_, _ = upstream.Write(prefix)
		}
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	// One direction ended; closing both unblocks the peer's pending Read (double-close with
	// handleFlow's deferred closes is harmless).
	client.Close()
	upstream.Close()
	<-done
}

// TProxyServer runs the transparent accept loop, deciding each flow through the gateway.
type TProxyServer struct {
	decide DecideFunc
	dial   DialFunc
	log    *slog.Logger
}

// NewTProxyServer builds the server from a gateway. The decision is metadata-only (the L4
// flow has no HTTP body): a Request carrying the original destination runs the pipeline, and
// a BLOCK action drops the flow. SNI/content inspection is a later increment.
func NewTProxyServer(gw *Gateway, log *slog.Logger) *TProxyServer {
	decide := func(ctx context.Context, origDst, src net.Addr, hint FlowHint) (bool, error) {
		dstIP, dstPort := addrHostPort(origDst)
		srcIP, srcPort := addrHostPort(src)
		dec, err := gw.Process(ctx, &Request{
			FlowID:    "tproxy-" + origDst.String() + "-" + src.String(),
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  "tcp",
			Host:      hint.SNI,     // the peeked SNI → the IOC domain match + host policy apply
			Body:      hint.Payload, // the peeked payload → the worker's content-signature engine (NIPS-2)
			Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
		})
		if err != nil {
			return false, err
		}
		return dec.GetAction() == corev1.Action_ACTION_BLOCK, nil
	}
	dialer := &net.Dialer{}
	dial := func(origDst net.Addr) (net.Conn, error) { return dialer.Dial("tcp", origDst.String()) }
	return &TProxyServer{decide: decide, dial: dial, log: log}
}

// Serve accepts redirected connections until ctx is done or the listener closes, handling each
// flow in its own goroutine (one stalled flow never blocks others).
func (s *TProxyServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go handleFlow(ctx, conn, conn.LocalAddr(), s.decide, s.dial, s.log)
	}
}

func addrHostPort(a net.Addr) (ip string, port uint32) {
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	n, _ := net.LookupPort("tcp", p)
	return h, uint32(n)
}
