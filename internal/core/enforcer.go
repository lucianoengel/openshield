package core

import (
	"context"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Enforcer is the enforcement plugin interface. It accepts a Decision and
// NOTHING else.
//
// It does not take the originating Event, the Classification, or any handle
// from which either could be retrieved. An enforcer therefore cannot learn
// which classifier matched, which pattern fired, or what the matched content
// was — the CrowdSec separation, and the reason enforcement points can be
// written independently of detection.
//
// This is enforced by the compiler, not by convention: there is no parameter
// through which classifier state could arrive. `internal/core/enforcerisolation`
// contains a package that must FAIL to compile, asserted in CI, because the only
// faithful test of "cannot" is a compilation that cannot succeed.
//
// Phase 1 is observe-and-audit only (D1): Decisions are recorded and no
// Enforcer is invoked. The contract is defined now because it is expensive to
// change later; only its execution is deferred.
type Enforcer interface {
	// Capabilities reports which actions this enforcer can carry out. The
	// policy engine asks only "can you enforce this Decision" — never how the
	// Decision was reached.
	Capabilities() []corev1.Action

	// Enforce carries out the Decision. Returning an error means enforcement
	// failed, which is itself an auditable event — silence is not an option.
	Enforce(ctx context.Context, d *corev1.Decision) error
}

// CanEnforce reports whether an enforcer advertises the Decision's action.
func CanEnforce(e Enforcer, d *corev1.Decision) bool {
	for _, a := range e.Capabilities() {
		if a == d.GetAction() {
			return true
		}
	}
	return false
}
