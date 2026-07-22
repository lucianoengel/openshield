package peerueba_test

import (
	"math"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
)

func subjectSet(a *peerueba.Analyzer) map[string]bool {
	m := map[string]bool{}
	for _, s := range a.Snapshot() {
		m[s.Subject] = true
	}
	return m
}

// SIEM-5b: WithSnapshot rejects a corrupt restored entry (NaN/±Inf/negative count or empty subject),
// and Prune removes a decayed-below-threshold subject (reporting it) while sparing an active one.
func TestPruneAndCorruptRestore(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	a := peerueba.New(
		peerueba.WithClock(func() time.Time { return t0 }),
		peerueba.WithSnapshot([]peerueba.SubjectState{
			{Subject: "active", Count: 10, Last: t0},
			{Subject: "cold", Count: 1, Last: t0.Add(-100 * peerueba.DefaultHalfLife)}, // decayed ≈ 0
			{Subject: "nan", Count: math.NaN(), Last: t0},
			{Subject: "inf", Count: math.Inf(1), Last: t0},
			{Subject: "neg", Count: -3, Last: t0},
			{Subject: "", Count: 5, Last: t0},
		}),
	)

	have := subjectSet(a)
	for _, bad := range []string{"nan", "inf", "neg", ""} {
		if have[bad] {
			t.Errorf("WithSnapshot restored a corrupt entry %q — it must be dropped", bad)
		}
	}
	if !have["active"] || !have["cold"] {
		t.Fatalf("WithSnapshot dropped a valid entry: have=%v", have)
	}

	pruned := a.Prune(peerueba.PruneThreshold)
	seen := map[string]bool{}
	for _, id := range pruned {
		seen[id] = true
	}
	if !seen["cold"] {
		t.Errorf("Prune did not report the decayed subject; pruned=%v", pruned)
	}
	if seen["active"] {
		t.Error("Prune removed the still-active subject")
	}
	after := subjectSet(a)
	if after["cold"] {
		t.Error("the decayed subject is still present after Prune")
	}
	if !after["active"] {
		t.Error("the active subject was wrongly pruned")
	}
}
