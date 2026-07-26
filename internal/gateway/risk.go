package gateway

import "sync"

// RiskStore holds the latest published per-subject risk score for continuous
// verification (D89). The control plane computes risk (peer-UEBA, D54) and PUBLISHES
// it (the server->gateway signed channel is A.5b); the gateway reads it here and the
// LOCAL policy decides — the server informs, the gateway decides, the server never
// commands access (the T2 model, preserving D14).
//
// A subject with no entry has no risk (has=false): absent risk means "analytics is
// quiet", NOT danger, so the policy does not deny on a missing score — the opposite
// fail-direction from device posture, which fails closed when absent (D85). Both
// expose their absence (D28); the safe direction differs because they mean different
// things.
type RiskStore struct {
	mu     sync.RWMutex
	scores map[string]float64
}

func NewRiskStore() *RiskStore { return &RiskStore{scores: map[string]float64{}} }

// Set records published risk for a subject (pseudonymous, D23). It RAISES but never lowers.
//
// Cross-domain entity risk (XDR-7) and per-subject peer-UEBA risk (D91) both publish here, and turning the
// former on must not be able to make a subject look SAFER than the behavioural signal already says it is:
// the highest signal wins, so a decision fails toward suspicion.
//
// The honest cost of that asymmetry: risk is STICKY — it decays only when the process restarts, until a
// future ticket adds explicit decay. Stated rather than hidden, because a number that only ever rises will
// eventually pin an asset if nothing ages it.
func (r *RiskStore) Set(subject string, score float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.scores[subject]; ok && cur >= score {
		return
	}
	r.scores[subject] = score
}

// Get returns the subject's latest risk, or has=false when none was published.
func (r *RiskStore) Get(subject string) (float64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scores[subject]
	return s, ok
}
