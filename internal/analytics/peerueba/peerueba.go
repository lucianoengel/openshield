// Package peerueba is peer-baseline UEBA — the real architecture test (D26).
//
// It is a genuinely NEW SHAPE of capability: STATEFUL (it accumulates behaviour
// over time) and CROSS-ENTITY (a subject is risky RELATIVE TO ITS PEERS, not by
// a per-event rule). That is precisely why D26 named it the honest test of the
// zero-core-change claim — and building it confirmed the claim's narrow form: it
// needed exactly ONE small core change, a `Dispatcher.ResolveContext` hook,
// because the dispatcher built State with a nil Context and no injection point.
//
// The analyzer lives entirely OUTSIDE core (core must not import it — the
// capability boundary). It produces a core.Context that the policy consults; it
// is server-side, off by default, with its own consent/DPIA gate (D23).
package peerueba

import (
	"math"
	"sync"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Analyzer accumulates per-subject activity and computes peer-relative risk. It
// is thread-safe: Observe (from the event stream) and ContextFor / the resolver
// (from the pipeline) run concurrently.
type Analyzer struct {
	mu      sync.Mutex
	counts  map[string]float64
	version uint64 // bumps as the population changes, for D27 context_version
}

// New returns an empty analyzer.
func New() *Analyzer { return &Analyzer{counts: map[string]float64{}} }

// Observe records one unit of activity for a subject. Called for each event in
// the stream (out of band from the permission window — the analyzer aggregates
// asynchronously; the Context is a resolved VALUE, D28).
func (a *Analyzer) Observe(subjectID string) {
	if subjectID == "" {
		return
	}
	a.mu.Lock()
	a.counts[subjectID]++
	a.version++
	a.mu.Unlock()
}

// ContextFor computes the subject's risk RELATIVE to its peers: a z-score of its
// activity against the population mean/stddev, squashed to [0,1]. This is the
// cross-entity signal — a subject far above its peers scores high. Returns nil
// for an unknown subject or a population too small to have peers.
func (a *Analyzer) ContextFor(subjectID string) *core.Context {
	a.mu.Lock()
	defer a.mu.Unlock()

	cnt, ok := a.counts[subjectID]
	if !ok || len(a.counts) < 2 {
		return nil // no peers to compare against
	}
	mean, std := a.meanStd()
	risk := 0.0
	if std > 0 {
		z := (cnt - mean) / std
		// Squash a positive z-score to [0,1]; only ABOVE-peer activity is risky.
		if z > 0 {
			risk = 1 - math.Exp(-z) // 0 at the mean, →1 far above peers
		}
	}
	return &core.Context{
		Version:      versionString(a.version),
		RiskScore:    risk,
		HasRiskScore: true,
	}
}

// meanStd of the population's activity counts (caller holds the lock).
func (a *Analyzer) meanStd() (mean, std float64) {
	n := float64(len(a.counts))
	var sum float64
	for _, c := range a.counts {
		sum += c
	}
	mean = sum / n
	var ss float64
	for _, c := range a.counts {
		d := c - mean
		ss += d * d
	}
	std = math.Sqrt(ss / n)
	return mean, std
}

// Resolver returns a Context resolver for the Dispatcher: it reads the event's
// pseudonymous subject (D23) and returns that subject's peer-relative Context.
// This is the adapter plugged into the ONE core hook.
func (a *Analyzer) Resolver() func(*corev1.Event) *core.Context {
	return func(e *corev1.Event) *core.Context {
		return a.ContextFor(e.GetSubject().GetPseudonymousId())
	}
}

func versionString(v uint64) string {
	// A monotonic snapshot id (D27) — a Decision records which context applied.
	const digits = "0123456789"
	if v == 0 {
		return "ctx-0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v%10]}, b...)
		v /= 10
	}
	return "ctx-" + string(b)
}
