package main

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/lucianoengel/openshield/internal/connectors/dns"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// dnsListener binds the DNS query connector (NIPS-3) and returns a Listener whose sink feeds
// each parsed query — as a NetworkSubject Event — into the SAME event channel the file
// watchers use, so live DNS resolution runs through the pipeline (classify → policy → decide →
// audit) exactly like a file event. Egress policy on resolved names and DNS-tunnelling
// detection (dns.TunnelScore) become live rather than parser-only. The engine stays
// observe-only (D1); this is an additional SOURCE, not an enforcement path.
//
// Each query is given a monotonic flow id (the connector mints the opaque handle, as the
// gateway does per request), and the datagram's source IP is carried into the Event — a
// network decision that could not say who asked is not actionable. A send races the context:
// on shutdown the send is abandoned rather than blocking the receive loop.
func dnsListener(ctx context.Context, addr string, events chan<- *corev1.Event, log *slog.Logger) (*dns.Listener, error) {
	var flowSeq atomic.Uint64
	return dns.Listen(addr, func(srcIP string, q dns.Query) {
		flowID := strconv.FormatUint(flowSeq.Add(1), 10)
		select {
		case events <- dns.ToEvent(flowID, srcIP, q):
		case <-ctx.Done():
		}
	}, log)
}
