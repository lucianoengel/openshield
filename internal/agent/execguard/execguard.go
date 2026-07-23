// Package execguard wires the inline exec-deny path (HIPS-3): it turns an exec-permission event into a
// process-exec pipeline event, runs it through the engine, and hands the decision to the watchdog's
// ExecEvaluator, which answers the kernel DENY iff the decision is DENY_EXEC (and fail-opens otherwise).
// It lives here — not in the watchdog package — so the watchdog stays engine-free (no import cycle).
package execguard

import (
	"context"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// ExecProcessor is the slice of the engine the decider needs — an interface so the wiring is testable
// without a full engine and the package depends on the behavior, not the concrete *engine.Engine.
type ExecProcessor interface {
	Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error)
}

// Decider builds the production watchdog.ExecDecider (HIPS-3): it turns an exec-permission event into an
// EVENT_KIND_PROCESS_EXEC event (the binary path and pid), runs the pipeline, and returns the decision's
// action for the ExecEvaluator. A Process error is PROPAGATED so the watchdog fail-opens (an evaluation
// failure must allow the exec, never hang or spuriously block it).
func Decider(p ExecProcessor) ExecDecider {
	return func(ctx context.Context, e watchdog.PermissionEvent) (corev1.Action, error) {
		ev := &corev1.Event{
			Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
			Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
				Pid:      e.PID,
				ExecPath: e.Path,
			}},
		}
		dec, err := p.Process(ctx, ev)
		if err != nil {
			return corev1.Action_ACTION_UNSPECIFIED, err
		}
		return dec.GetAction(), nil
	}
}
