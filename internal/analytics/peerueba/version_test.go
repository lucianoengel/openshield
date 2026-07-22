package peerueba_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
)

// SEC-10: two analyzers seeded with different start versions (simulating two process runs
// with reserved version blocks) never produce the same context_version for the same activity —
// so a Decision's context_version is unambiguous across restarts (D27).
func TestWithStartVersionAvoidsCollision(t *testing.T) {
	run := func(base uint64) string {
		a := peerueba.New(peerueba.WithStartVersion(base))
		// Observe 3 subjects so a peer baseline exists (ContextFor needs >=2 peers).
		a.Observe("subject-a")
		a.Observe("subject-b")
		a.Observe("subject-c")
		c := a.ContextFor("subject-a")
		if c == nil {
			t.Fatal("no context — need more peers")
		}
		return c.Version
	}
	// Run 1 starts at base 0 (the old buggy default); run 2 at a reserved higher base.
	v1 := run(0)
	v2 := run(1_000_000_000)
	if v1 == v2 {
		t.Errorf("context_version collided across runs: %q == %q — restart attribution ambiguous", v1, v2)
	}
	// A fresh unseeded analyzer with the SAME base as run 1 WOULD collide — proving the base
	// is what disambiguates (a control against a false pass).
	if run(0) != v1 {
		t.Errorf("same base gave different versions %q vs %q — not deterministic", run(0), v1)
	}
}
