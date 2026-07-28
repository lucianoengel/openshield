package main

import (
	"context"
	"log/slog"
	"time"
)

// DISCARD REPORTING FOR THE ENDPOINT LISTENERS (D348).
//
// The control plane publishes its listeners' refusal counts on /metrics. The ENGINE has no HTTP
// surface, and giving it one is a decision about the product's attack surface — a port on every
// endpoint — not something to do as a side effect of adding a counter. So it reports in the one
// channel it already has.
//
// ONLY WHEN A COUNTER HAS MOVED. A periodic line that fires unconditionally becomes noise, gets
// filtered, and turns a signal into a silence with extra steps. A healthy listener says nothing; one
// that starts discarding says so every interval until it stops.
//
// The asymmetry is deliberate: a missed report is an unnoticed gap in visibility, a repeated one is a
// duplicated log line.

// discardCounter names a counter and reads it.
type discardCounter struct {
	name string
	read func() int64
}

// reportDiscards logs the listeners' counters whenever one increases.
func reportDiscards(ctx context.Context, log *slog.Logger, listener string, interval time.Duration,
	counters ...discardCounter) {
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
		attrs := []any{slog.String("listener", listener)}
		moved := false
		for i, c := range counters {
			v := c.read()
			if v > last[i] {
				moved = true
			}
			last[i] = v
			if v > 0 {
				// Every non-zero counter is included once ANY of them moves, so the line reads as a
				// state rather than a delta — an operator seeing it for the first time gets the whole
				// picture, not the one number that happened to change this interval.
				attrs = append(attrs, slog.Int64(c.name, v))
			}
		}
		if moved {
			log.Warn("engine: listener is DISCARDING input — these messages are not in the pipeline "+
				"and are not in the ledger", attrs...)
		}
	}
}
