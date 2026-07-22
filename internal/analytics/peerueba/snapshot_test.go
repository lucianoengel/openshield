package peerueba_test

import (
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
)

// SIEM-5: a restored analyzer reproduces the EXACT risk of the original. A frozen clock makes the
// equality bit-exact (no decay drift between the two evaluations) — the point is that the persisted
// {count, last} pair is a complete, lossless representation of the baseline.
func TestSnapshotRoundTripReproducesRisk(t *testing.T) {
	frozen := time.Unix(1700000000, 0).UTC()
	clock := peerueba.WithClock(func() time.Time { return frozen })

	orig := peerueba.New(clock)
	for _, s := range []string{"s1", "s2", "s3", "s4"} {
		for i := 0; i < 10; i++ {
			orig.Observe(s)
		}
	}
	for i := 0; i < 200; i++ {
		orig.Observe("outlier")
	}

	snap := orig.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("snapshot has %d subjects, want 5", len(snap))
	}

	// A fresh analyzer seeded from the snapshot must compute the SAME risk for each subject.
	restored := peerueba.New(clock, peerueba.WithSnapshot(snap))
	for _, subj := range []string{"outlier", "s1", "s2", "s3", "s4"} {
		o := orig.ContextFor(subj)
		r := restored.ContextFor(subj)
		if o == nil || r == nil {
			t.Fatalf("%s: nil context (orig=%v restored=%v)", subj, o, r)
		}
		if o.RiskScore != r.RiskScore {
			t.Errorf("%s: restored risk %.12f != original %.12f — snapshot is lossy", subj, r.RiskScore, o.RiskScore)
		}
	}

	// An empty snapshot yields a cold analyzer with no baseline.
	cold := peerueba.New(clock, peerueba.WithSnapshot(nil))
	if cold.ContextFor("outlier") != nil {
		t.Error("a cold analyzer (empty snapshot) reported a baseline it never had")
	}
}
