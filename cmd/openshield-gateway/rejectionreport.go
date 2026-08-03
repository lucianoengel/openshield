package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// REJECTION REPORTING FOR THE GATEWAY'S SIGNED CHANNELS.
//
// Every one of these counters was written with a comment saying the thing it counts must be visible:
//
//	risk       "updates dropped for failing verification (observable, SEC-1)" …
//	           "a forged-risk flood is observable, not silent"
//	posture    per-agent verification failures (SEC-12)
//	attest     attestation responses refused (ZT-1)
//	intent     "a forged-intent flood must be observable, not silent"
//
// NONE OF THEM WERE. Every `Rejected.Load()` in the tree was in a test — the tests observe the counter and
// prove it increments, which reads as proving the property, but the property is "an operator can see a
// forged-signature flood" and no operator could. The gateway had no counter-surfacing mechanism at all,
// and main.go discarded the subscriber references as it created them, so the numbers were unreachable even
// in principle.
//
// This is the same defect as D415 (eleven control-plane counters) and D417 (the pipeline's timeout
// counter). What makes this instance the worst of the three is what is being counted: a rising rejection
// rate on a SIGNED channel is somebody presenting forged risk, forged posture or a forged intent. It is
// the signal, not the noise.
//
// The gateway, like the engine, has no HTTP surface — giving it one is a decision about attack surface,
// not a side effect of reporting a counter (D348) — so this reports in the channel it already has, on the
// same "only when a counter has moved" discipline: a healthy gateway says nothing, one being probed says
// so every interval until it stops.

// rejectionCounter names a counter and reads it.
type rejectionCounter struct {
	name string
	read func() int64
}

// reportDegraded starts the DEGRADED reporter for the counters EVERY gateway has, whatever it is serving,
// plus any mode-specific ones the caller adds.
//
// It exists because the previous version of this reporter lived entirely inside runAccessMode, and
// runAccessMode is an ALTERNATIVE to the ordinary proxy path rather than a stage of it — main returns
// straight after calling it. So a gateway doing the thing gateways mostly do reported none of this: not a
// suppressed enforcement, not a dropped audit append, not a fleet-control forgery flood.
//
// The block carried a comment explaining that it had been deliberately hoisted OUT of the NATS
// conditional, because "a gateway deployed without NATS still enforces … and would have reported none of
// it. That is the same defect this whole thread is about, reintroduced one commit after fixing it." The
// hoist was correct and one scope short: the same argument applies to the mode. Hence a function, so the
// next caller has to be given the counters rather than having to remember to copy them.
func reportDegraded(ctx context.Context, log *slog.Logger, gw *gateway.Gateway, extra ...rejectionCounter) {
	// FleetControlCounts returns (0, 0) when no subscriber exists, so those two read zero rather than
	// needing their own conditional.
	degraded := []rejectionCounter{
		{"fleet_control_applied", func() int64 { a, _ := gw.FleetControlCounts(); return a }},
		{"fleet_control_rejected", func() int64 { _, r := gw.FleetControlCounts(); return r }},
		{"enforcement_audit_dropped", gw.EnforceAuditDropped},
	}
	if gw.KillSwitch != nil {
		degraded = append(degraded, rejectionCounter{"enforcement_suppressed", gw.KillSwitch.Suppressions.Load})
	}
	go reportRejections(ctx,
		log,
		"gateway: DEGRADED — enforcement is being suppressed, fleet control is arriving, or entity "+
			"links are failing. Detection continues; some of what you expect to be blocked is not.",
		envDuration("OPENSHIELD_DISCARD_REPORT_INTERVAL", time.Minute),
		append(degraded, extra...)...)
}

// msg is passed in because two groups share this discipline with different meanings: signed-channel
// REJECTIONS (someone presenting forged material) and DEGRADED operation (enforcement suppressed by the
// kill switch, entity links that failed). Same "only when it moves" rule; different thing to say.
func reportRejections(ctx context.Context, log *slog.Logger, msg string, interval time.Duration, counters ...rejectionCounter) {
	if len(counters) == 0 {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	last := make([]int64, len(counters))
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		attrs := []any{}
		moved := false
		for i, c := range counters {
			v := c.read()
			if v > last[i] {
				moved = true
			}
			last[i] = v
			if v > 0 {
				// Every non-zero counter is included once ANY of them moves, so the line reads as a state
				// rather than a delta: an operator seeing it for the first time gets the whole picture.
				attrs = append(attrs, slog.Int64(c.name, v))
			}
		}
		if moved {
			log.Warn(msg, attrs...)
		}
	}
}
