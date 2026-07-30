package main

import (
	"context"
	"log/slog"
	"time"
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
