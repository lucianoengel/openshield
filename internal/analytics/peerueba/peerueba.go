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
//
// The baseline is hardened two ways (D61): it is LEAVE-ONE-OUT — a subject is
// compared to its PEERS, never to a baseline its own activity has inflated — and
// it DECAYS over time, so a steady-but-busy subject settles near its peers
// instead of climbing forever into a false anomaly. It remains a statistical
// baseline, not a trained detector.
package peerueba

import (
	"math"
	"sync"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DefaultHalfLife is how long it takes accumulated activity to decay by half. A
// subject sustaining a steady rate converges to a bounded level rather than
// growing without limit.
const DefaultHalfLife = time.Hour

// minRelSpread floors the peer standard deviation at this fraction of the mean,
// so a z-score is not computed against a near-zero spread (which would turn decay
// noise into false anomalies). A subject roughly this far above uniform peers
// scores z≈1.
const minRelSpread = 0.1

// entry is a subject's decaying activity: count as of the last update time.
type entry struct {
	count float64
	last  time.Time
}

// Analyzer accumulates per-subject activity and computes peer-relative risk. It
// is thread-safe: Observe (from the event stream) and ContextFor / the resolver
// (from the pipeline) run concurrently.
type Analyzer struct {
	mu       sync.Mutex
	subjects map[string]*entry
	version  uint64 // bumps as the population changes, for D27 context_version
	now      func() time.Time
	halfLife time.Duration
}

// Option configures an Analyzer.
type Option func(*Analyzer)

// WithClock injects a time source (default time.Now) so decay is deterministic
// in tests — the analyzer never reads wall-clock directly.
func WithClock(f func() time.Time) Option { return func(a *Analyzer) { a.now = f } }

// WithHalfLife overrides the decay half-life (default DefaultHalfLife).
func WithHalfLife(d time.Duration) Option { return func(a *Analyzer) { a.halfLife = d } }

// SubjectState is a subject's persisted baseline (SIEM-5): its decayed activity Count as of
// Last. It is the COMPLETE representation an analyzer needs to resume — decay is computed
// forward from Last at query time, so storing and restoring this pair verbatim reproduces the
// exact risk. Serializable for the control plane to persist across restarts.
type SubjectState struct {
	Subject string
	Count   float64
	Last    time.Time
}

// WithSnapshot seeds a new analyzer with a previously-taken Snapshot (SIEM-5), so a restart
// resumes the warm baseline instead of cold-starting (which would blind the fleet to peer
// anomalies for a decay half-life). The stored count/last are restored VERBATIM — no decay is
// applied here, because ContextFor decays forward from Last at query time; applying it again
// would double-count. An empty snapshot yields a cold analyzer.
func WithSnapshot(states []SubjectState) Option {
	return func(a *Analyzer) {
		for _, s := range states {
			if s.Subject == "" {
				continue
			}
			a.subjects[s.Subject] = &entry{count: s.Count, last: s.Last}
		}
	}
}

// WithStartVersion seeds the context-version counter (SEC-10). The version resets to 0 on a
// process restart, so without a persisted base "ctx-0" from THIS run would collide with
// "ctx-0" from a PRIOR run — two different populations sharing one context_version, breaking
// D27's "which context did this Decision see". The control plane reserves a monotonic base
// per startup and seeds it here, so a version string is unique across restarts.
func WithStartVersion(base uint64) Option { return func(a *Analyzer) { a.version = base } }

// New returns an empty analyzer.
func New(opts ...Option) *Analyzer {
	a := &Analyzer{subjects: map[string]*entry{}, now: time.Now, halfLife: DefaultHalfLife}
	for _, o := range opts {
		o(a)
	}
	return a
}

// decayedAt returns a subject's count decayed forward to time t (does not mutate).
func (a *Analyzer) decayedAt(e *entry, t time.Time) float64 {
	if e.count == 0 {
		return 0
	}
	dt := t.Sub(e.last).Seconds()
	if dt <= 0 {
		return e.count
	}
	return e.count * math.Exp(-math.Ln2*dt/a.halfLife.Seconds())
}

// Observe records one unit of activity for a subject. Called for each event in
// the stream (out of band from the permission window — the analyzer aggregates
// asynchronously; the Context is a resolved VALUE, D28). Prior activity is decayed
// to now BEFORE the unit is added, so the stored count is always as-of its last
// update.
func (a *Analyzer) Observe(subjectID string) {
	if subjectID == "" {
		return
	}
	t := a.now()
	a.mu.Lock()
	e := a.subjects[subjectID]
	if e == nil {
		e = &entry{last: t}
		a.subjects[subjectID] = e
	}
	e.count = a.decayedAt(e, t)
	e.last = t
	e.count++
	a.version++
	a.mu.Unlock()
}

// ContextFor computes the subject's risk RELATIVE to its peers: a z-score of its
// (decayed) activity against the OTHER subjects' mean/stddev — LEAVE-ONE-OUT, so
// the subject never contaminates the baseline it is judged against. Returns nil
// for an unknown subject or when fewer than two OTHER subjects exist (no peers to
// compare against).
func (a *Analyzer) ContextFor(subjectID string) *core.Context {
	a.mu.Lock()
	defer a.mu.Unlock()

	self, ok := a.subjects[subjectID]
	if !ok {
		return nil
	}
	t := a.now()
	selfCount := a.decayedAt(self, t)

	peers := make([]float64, 0, len(a.subjects))
	for id, e := range a.subjects {
		if id == subjectID {
			continue
		}
		peers = append(peers, a.decayedAt(e, t))
	}
	if len(peers) < 2 {
		return nil // not enough peers to have a baseline
	}

	mean, std := meanStd(peers)
	// Floor the spread at a fraction of the mean (a coefficient-of-variation
	// floor). A z-score over NEAR-UNIFORM peers is meaningless — dividing by a
	// near-zero std makes an infinitesimal deviation look like a huge anomaly, which
	// time decay makes acute (it perturbs otherwise-equal counts by tiny amounts).
	// So a subject must be MEANINGFULLY above uniform peers, not just above the
	// noise, to score. If the mean is zero there is no activity to be above.
	if floor := mean * minRelSpread; std < floor {
		std = floor
	}
	risk := 0.0
	if std > 0 {
		z := (selfCount - mean) / std
		// Squash a positive z-score to [0,1]; only ABOVE-peer activity is risky.
		if z > 0 {
			risk = 1 - math.Exp(-z) // 0 at the peer mean, →1 far above peers
		}
	}
	return &core.Context{
		Version:      versionString(a.version),
		RiskScore:    risk,
		HasRiskScore: true,
	}
}

// Snapshot returns the analyzer's per-subject baseline for persistence (SIEM-5). It copies the
// stored {count, last} verbatim under the lock — NOT decayed to now — so restoring it reproduces
// the exact query-time risk (decay is applied at query time from Last). The order is
// unspecified.
func (a *Analyzer) Snapshot() []SubjectState {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]SubjectState, 0, len(a.subjects))
	for id, e := range a.subjects {
		out = append(out, SubjectState{Subject: id, Count: e.count, Last: e.last})
	}
	return out
}

// meanStd of a slice of counts.
func meanStd(xs []float64) (mean, std float64) {
	n := float64(len(xs))
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / n
	var ss float64
	for _, x := range xs {
		d := x - mean
		ss += d * d
	}
	return mean, math.Sqrt(ss / n)
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
