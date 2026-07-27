// Package execguard wires the inline exec-deny path (HIPS-3): it turns an exec-permission event into a
// process-exec pipeline event, runs it through the engine, and hands the decision to the watchdog's
// ExecEvaluator, which answers the kernel DENY iff the decision is DENY_EXEC (and fail-opens otherwise).
// It lives here — not in the watchdog package — so the watchdog stays engine-free (no import cycle).
package execguard

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// ExecProcessor is the slice of the engine the decider needs — an interface so the wiring is testable
// without a full engine and the package depends on the behavior, not the concrete *engine.Engine.
type ExecProcessor interface {
	Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error)
}

// execSeq makes each exec event's id unique within a run. The pid alone is not enough: pids are reused,
// and two events sharing an id would collapse into one in any store keyed by it.
var execSeq atomic.Uint64

// Decider builds the production watchdog.ExecDecider (HIPS-3): it turns an exec-permission event into an
// EVENT_KIND_PROCESS_EXEC event (the binary path and pid), runs the pipeline, and returns the decision's
// action for the ExecEvaluator. A Process error is PROPAGATED so the watchdog fail-opens (an evaluation
// failure must allow the exec, never hang or spuriously block it).
func Decider(p ExecProcessor) ExecDecider {
	return func(ctx context.Context, e watchdog.PermissionEvent) (corev1.Action, error) {
		// PROVENANCE IS THE PRODUCER'S JOB, and omitting it broke this path entirely (D301).
		//
		// `core.ValidateEvent` requires an event id and a connector id; the engine's `attribute` stamps
		// the subject, the agent, the timestamp and the purpose, but an event's IDENTITY and its SOURCE
		// are not the engine's to invent. Without them every exec-permission decision failed validation,
		// `Process` returned an error, and the watchdog FAILED OPEN — so the engine-backed inline exec
		// gate never denied anything, while the agent logged "HIPS-3 inline exec prevention ACTIVE".
		//
		// It is the exact shape of the fanotify connector's missing purpose (D296): a producer omitting a
		// provenance field, every package test constructing events that already have it, and the failure
		// visible only by running the real path.
		ev := &corev1.Event{
			EventId:     fmt.Sprintf("exec-%d-%d", e.PID, execSeq.Add(1)),
			ConnectorId: "execmon",
			Kind:        corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
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
