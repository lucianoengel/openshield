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

// TargetedEnforcer is an Enforcer that acts on a specific TARGET (a file path, a
// connection) supplied by the caller, not carried in the Decision.
//
// The Decision carries the verdict and no target (D39): widening the hash-chained
// Decision contract to carry an enforcement target is a deferred core change. But
// enforcement of a file genuinely needs to know WHICH file. So the engine, which
// holds the originating event, supplies the target here — separately from the
// Decision. The enforcer still receives only the Decision for the VERDICT (D14);
// the target is the subject of enforcement, not detection detail, exactly as
// CrowdSec's decision carries the IP to act on.
type TargetedEnforcer interface {
	Enforcer
	EnforceTarget(ctx context.Context, d *corev1.Decision, target string) error
}
