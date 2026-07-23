package gateway

import (
	"context"
	"io"
	"log/slog"
	"net"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Transparent (TPROXY) inline data-plane (NIPS-1): the gateway can act as an inline network
// IPS, not only an explicit HTTP proxy. A TPROXY nftables/iptables rule redirects a TCP flow
// to a transparent listener (ListenTransparent, linux); each accepted connection's LocalAddr
// is the ORIGINAL destination the client meant to reach (TPROXY preserves it). The flow is
// decided through the pipeline on its metadata and either DROPPED (a real inline block at L4)
// or SPLICED bidirectionally to its original destination.
//
// Egress fail-open is load-bearing (ADR-8/D73/D17): a pipeline error forwards the flow rather
// than dropping it — inline prevention degrades to a passive wire, never a network outage.

// DecideFunc decides a flow on its metadata: block reports whether to drop the flow. An error
// is a DETECTION failure and MUST be treated as allow by the caller (fail-open).
type DecideFunc func(ctx context.Context, origDst, src net.Addr) (block bool, err error)

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

	block, err := decide(ctx, origDst, client.RemoteAddr())
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
			log.Info("tproxy: flow dropped by policy", "dst", origDst.String(), "src", client.RemoteAddr().String())
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
	splice(client, upstream)
}

// splice copies bytes bidirectionally between the client and the upstream until either side
// closes; when one direction ends it closes both connections to unblock the other, then waits
// for both copies to finish.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// One direction ended; closing both unblocks the peer's pending Read (double-close with
	// handleFlow's deferred closes is harmless).
	a.Close()
	b.Close()
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
	decide := func(ctx context.Context, origDst, src net.Addr) (bool, error) {
		dstIP, dstPort := addrHostPort(origDst)
		srcIP, srcPort := addrHostPort(src)
		dec, err := gw.Process(ctx, &Request{
			FlowID:    "tproxy-" + origDst.String() + "-" + src.String(),
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  "tcp",
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
