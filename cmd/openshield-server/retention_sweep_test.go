package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestOneFailingPurgeDoesNotStopTheOthers (D483).
//
// The leader's retention tick was one straight-line closure: a failed fleet purge `return`ed, so the
// notify-dedupe prune and the view-audit purge never ran. Three unrelated tables and three separate
// retention obligations, coupled by nothing but the order somebody wrote them in — and the failure of
// the first silently stopped the other two from being enforced, while the one line on stderr named the
// fleet purge.
//
// THE COMPLIANCE HALF IS ASSERTED TOO. `retention_events` records purges that RAN, so an absence means
// either "failing for months" or "never due" — the counter is the only thing that distinguishes them,
// and /health is where an operator sees it.
//
// Mutation: change the `continue` in runRetentionSweep back to `return` → the two jobs after the failure
// never run and this FAILS. Mutation: drop the onFailure call → the counter half FAILS.
func TestOneFailingPurgeDoesNotStopTheOthers(t *testing.T) {
	var ran []string
	job := func(target string, rows int64, err error) retentionJob {
		return retentionJob{
			target: target, unit: target + " rows", policy: target + "=1h",
			cutoff: time.Now().Add(-time.Hour),
			run: func(context.Context, time.Time) (int64, error) {
				ran = append(ran, target)
				return rows, err
			},
		}
	}

	var recorded []string
	failures := 0
	runRetentionSweep(context.Background(), []retentionJob{
		job("fleet_telemetry", 0, errors.New("relation does not exist")),
		job("notify_dedupe", 3, nil),
		job("investigation_views", 7, nil),
	}, func(_ context.Context, target string, _ int64, _ time.Time, _ string) {
		recorded = append(recorded, target)
	}, func(string, error) { failures++ })

	if len(ran) != 3 {
		t.Errorf("only %v ran. One retention obligation failing must not stop the others: they are "+
			"separate tables and separate promises, and the ones that never ran are the ones nobody is "+
			"watching", ran)
	}
	// The failed one records NOTHING — a compliance event for a purge that did not happen would be
	// evidence of a deletion that never occurred.
	if len(recorded) != 2 || recorded[0] != "notify_dedupe" || recorded[1] != "investigation_views" {
		t.Errorf("compliance events recorded for %v, want the two purges that actually ran", recorded)
	}
	if failures != 1 {
		t.Errorf("the sweep counted %d failures, want 1 — without the counter, a purge failing for "+
			"months is indistinguishable from one that was never due, because the compliance report "+
			"shows an absence either way", failures)
	}
}

// TestASuccessfulSweepCountsNoFailures. The negative above is only meaningful against a sweep that does
// not count every run as a failure.
func TestASuccessfulSweepCountsNoFailures(t *testing.T) {
	failures, recorded := 0, 0
	runRetentionSweep(context.Background(), []retentionJob{{
		target: "investigation_views", cutoff: time.Now(),
		run: func(context.Context, time.Time) (int64, error) { return 0, nil },
	}}, func(context.Context, string, int64, time.Time, string) { recorded++ },
		func(string, error) { failures++ })

	if failures != 0 {
		t.Errorf("a clean sweep counted %d failures", failures)
	}
	// A ZERO-ROW purge still records: the report has to prove retention is EXECUTING on schedule, not
	// merely that rows were once deleted.
	if recorded != 1 {
		t.Errorf("a zero-row purge recorded %d compliance events, want 1 — otherwise a deployment with "+
			"nothing to purge is indistinguishable from one whose purge never runs", recorded)
	}
}
