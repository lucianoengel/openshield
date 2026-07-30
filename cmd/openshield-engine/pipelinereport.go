package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
)

// PIPELINE OUTCOME REPORTING.
//
// core.Metrics has counted Dispatched/Decided/Failed/TimedOut since the pipeline was written, and said why
// the split matters: "Timeouts are counted separately from failures because a rising timeout rate is its
// own signal: it is the cheapest way to detect an adversary manufacturing fail-open bypasses (D17)."
//
// NOTHING READ THEM. The counters incremented correctly, on the right events, for the right reasons, and
// no code path anywhere could observe the result — so the detection D17 calls cheapest was not available
// at any price. Same defect as the eleven control-plane counters (D415) and the SIEM ingest counters
// before those; this is its third appearance, in the component where it matters most.
//
// The engine has no HTTP surface and giving it one is a decision about the product's attack surface — a
// port on every endpoint — not something to do as a side effect of reporting a counter (D348). So this
// reports in the one channel the engine already has, following exactly the discard-report discipline.

// THE TRIGGER IS NOT THE FULL SET, and that is the one real difference from reportDiscards.
//
// Dispatched and Decided move on EVERY event, so "report whenever any counter moves" would log every
// interval forever on a healthy endpoint — the unconditional periodic line D348 warns turns a signal into
// a silence with extra steps. Only FAILED and TIMED-OUT trigger a line; all four are then included, so the
// line reads as a state and an operator seeing it for the first time gets the denominator too. A rising
// timeout count means nothing without the dispatch count beside it.
func reportPipelineOutcomes(ctx context.Context, log *slog.Logger, m *core.Metrics, interval time.Duration) {
	if m == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	var lastFailed, lastTimedOut int64
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		failed, timedOut := m.Failed.Load(), m.TimedOut.Load()
		if failed <= lastFailed && timedOut <= lastTimedOut {
			lastFailed, lastTimedOut = failed, timedOut
			continue
		}
		lastFailed, lastTimedOut = failed, timedOut
		log.Warn("engine: pipeline stages are FAILING or TIMING OUT — a stage that times out is answered "+
			"fail-open, so these events were not decided on their merits (D17/D18)",
			slog.Int64("dispatched", m.Dispatched.Load()),
			slog.Int64("decided", m.Decided.Load()),
			slog.Int64("failed", failed),
			slog.Int64("timed_out", timedOut))
	}
}
