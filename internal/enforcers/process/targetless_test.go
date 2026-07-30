package process_test

import (
	"context"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
)

// A TARGETLESS ENFORCE MUST FAIL, NOT SUCCEED QUIETLY.
//
// Both enforcers here act on a target: KILL_PROCESS needs a pid, DENY_EXEC needs an exec handle. The
// Enforcer interface also has a targetless Enforce, and both implementations return an error from it.
//
// Returning nil instead would be the worst available outcome — worse than a panic. The pipeline records
// what the enforcer reported, so a nil would be written to the audit ledger as an enforcement that
// SUCCEEDED, for a process that was never killed and an exec that was never denied. The operator's
// timeline would show the threat handled. D31: a gap must never be silent.
//
// Both were at 0% coverage, which is how a three-line guard quietly becomes a `return nil` during a
// refactor that "removed an unused error return".

func TestATargetlessEnforceIsAnErrorRatherThanASilentSuccess(t *testing.T) {
	for name, e := range map[string]interface {
		Enforce(context.Context, *corev1.Decision) error
	}{
		"kill": process.NewKillEnforcer(),
		"deny": process.NewDenyEnforcer(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if err := e.Enforce(context.Background(), &corev1.Decision{}); err == nil {
				t.Fatal("a targetless Enforce reported success — the ledger would record an enforcement " +
					"that never happened, and the operator's timeline would show the threat handled")
			}
			// A nil decision must not panic either: the enforcer is called from the pipeline, and a panic
			// in an enforcer takes down the agent that is supposed to be protecting the machine.
			if err := e.Enforce(context.Background(), nil); err == nil {
				t.Fatal("a targetless Enforce with a nil decision reported success")
			}
		})
	}
}

// Capabilities is how the pipeline decides which enforcer handles a decision. An enforcer claiming an
// action it cannot perform silently swallows that action; one that fails to claim its own is never called,
// and the decision goes unenforced with nothing reporting a problem.
func TestEachEnforcerClaimsExactlyItsOwnAction(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  []corev1.Action
		want corev1.Action
	}{
		{"kill", process.NewKillEnforcer().Capabilities(), corev1.Action_ACTION_KILL_PROCESS},
		{"deny", process.NewDenyEnforcer(nil).Capabilities(), corev1.Action_ACTION_DENY_EXEC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.got) != 1 {
				t.Fatalf("claims %d actions (%v), want exactly one", len(tc.got), tc.got)
			}
			if tc.got[0] != tc.want {
				t.Fatalf("claims %v, want %v", tc.got[0], tc.want)
			}
		})
	}
}
