package peerueba_test

import (
	"math"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// riskFor replicates the analyzer's scoring (z-score with the coefficient-of-
// variation std floor) so a test can compare leave-one-out against self-included
// on identical inputs.
func riskFor(self float64, peers []float64) float64 {
	n := float64(len(peers))
	var sum float64
	for _, p := range peers {
		sum += p
	}
	mean := sum / n
	var ss float64
	for _, p := range peers {
		d := p - mean
		ss += d * d
	}
	std := math.Sqrt(ss / n)
	if floor := mean * 0.1; std < floor {
		std = floor
	}
	if std <= 0 {
		return 0
	}
	z := (self - mean) / std
	if z <= 0 {
		return 0
	}
	return 1 - math.Exp(-z)
}

// 2.2 — leave-one-out: a strong outlier scores strictly HIGHER when the baseline
// excludes it than when its own activity is folded in (self-contamination).
func TestLeaveOneOutBeatsSelfIncluded(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	a := peerueba.New(peerueba.WithClock(func() time.Time { return fixed }))
	for _, s := range []string{"p1", "p2", "p3"} {
		for i := 0; i < 5; i++ {
			a.Observe(s)
		}
	}
	for i := 0; i < 100; i++ {
		a.Observe("outlier")
	}

	loo := a.ContextFor("outlier")
	if loo == nil || !loo.HasRiskScore {
		t.Fatal("no risk for the outlier")
	}
	// Self-included baseline over ALL counts (peers + the outlier itself).
	selfIncluded := riskFor(100, []float64{5, 5, 5, 100})
	if !(loo.RiskScore > selfIncluded) {
		t.Fatalf("leave-one-out risk %.4f not > self-included %.4f — self-contamination not removed",
			loo.RiskScore, selfIncluded)
	}

	// Fewer than two OTHER subjects → no baseline.
	solo := peerueba.New(peerueba.WithClock(func() time.Time { return fixed }))
	solo.Observe("only")
	solo.Observe("only")
	if solo.ContextFor("only") != nil {
		t.Error("a single-subject population produced a Context")
	}
	solo.Observe("one-peer")
	if solo.ContextFor("only") != nil {
		t.Error("one other subject is not enough peers, want nil")
	}
}

// 3.2 — decay: a subject whose burst is in the PAST fades below its still-active
// peers and stops being flagged, whereas a non-decaying cumulative count keeps it
// flagged forever (stale anomaly).
func TestDecayRetiresAStaleBurst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	half := time.Hour

	decaying := peerueba.New(peerueba.WithClock(clock), peerueba.WithHalfLife(half))
	// A non-decaying reference: a huge half-life ≈ cumulative counting.
	cumulative := peerueba.New(peerueba.WithClock(clock), peerueba.WithHalfLife(1_000_000*time.Hour))

	burst := func(a *peerueba.Analyzer) {
		for _, s := range []string{"p1", "p2"} {
			for i := 0; i < 5; i++ {
				a.Observe(s)
			}
		}
		for i := 0; i < 50; i++ {
			a.Observe("spiker")
		}
	}
	burst(decaying)
	burst(cumulative)

	// At t0 the spiker is a genuine outlier in BOTH.
	if r := decaying.ContextFor("spiker"); r == nil || r.RiskScore < 0.7 {
		t.Fatalf("spiker not flagged at the time of its burst: %v", r)
	}

	// Time passes (10 half-lives); the peers stay active, the spiker goes silent.
	now = now.Add(10 * half)
	for _, a := range []*peerueba.Analyzer{decaying, cumulative} {
		for _, s := range []string{"p1", "p2"} {
			for i := 0; i < 5; i++ {
				a.Observe(s)
			}
		}
	}

	dec := decaying.ContextFor("spiker")
	cum := cumulative.ContextFor("spiker")
	if dec == nil || cum == nil {
		t.Fatal("nil context after time passed")
	}
	t.Logf("stale spiker risk — decaying=%.3f  cumulative=%.3f", dec.RiskScore, cum.RiskScore)
	// With decay the stale burst has faded below the active peers → no longer an
	// anomaly; without decay it is still flagged.
	if dec.RiskScore >= 0.5 {
		t.Errorf("decayed stale burst still flagged (risk %.3f) — decay did not retire it", dec.RiskScore)
	}
	if !(cum.RiskScore > dec.RiskScore) {
		t.Errorf("cumulative risk %.3f not > decayed %.3f — decay is not what retired the burst",
			cum.RiskScore, dec.RiskScore)
	}
}

// 3.3 — the public API and context_version (D53) are unchanged: Observe /
// ContextFor / Resolver still work and emit a version.
func TestPublicAPIUnchanged(t *testing.T) {
	a := peerueba.New()
	for _, s := range []string{"a", "b", "c"} {
		a.Observe(s)
	}
	for i := 0; i < 20; i++ {
		a.Observe("hot")
	}
	ctx := a.Resolver()(&corev1.Event{Subject: &corev1.Subject{PseudonymousId: "hot"}})
	if ctx == nil || !ctx.HasRiskScore || ctx.Version == "" {
		t.Fatalf("Resolver/ContextFor did not produce a versioned risk Context: %+v", ctx)
	}
}
