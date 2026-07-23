package watchdog

import (
	"context"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// ExecDecider decides an exec-permission event's action by running the pipeline (HIPS-3). It returns the
// pipeline's Action for the exec — production backs it with engine.Process over an
// EVENT_KIND_PROCESS_EXEC event; a decider ERROR is propagated so the watchdog FAIL-OPENS (an evaluation
// crash must never hang an exec). It is a func, not the engine, so this package stays engine-free (no
// import cycle) and the evaluator is testable in isolation.
type ExecDecider func(ctx context.Context, e PermissionEvent) (corev1.Action, error)

// ExecEvaluator maps an exec-permission decision to a watchdog Verdict (HIPS-3, T1): the ONLY action
// that blocks an exec is ACTION_DENY_EXEC — a decision to inline-refuse the execution, answered FAN_DENY
// by the watchdog. Every other action (ALLOW, ALERT, KILL_PROCESS, …) allows the exec (KILL acts
// post-exec, not here; a mis-decision degrades to allow — availability over a false block, D17). A
// decider error is returned so the watchdog fail-opens (never hang an exec on a crash).
type ExecEvaluator struct {
	Decide ExecDecider
}

func (x ExecEvaluator) Evaluate(ctx context.Context, e PermissionEvent) (Verdict, error) {
	action, err := x.Decide(ctx, e)
	if err != nil {
		return VerdictAllow, err // propagate → the watchdog fail-opens (allow + audit)
	}
	if action == corev1.Action_ACTION_DENY_EXEC {
		return VerdictBlock, nil // inline refuse the exec
	}
	return VerdictAllow, nil
}

var _ Evaluator = ExecEvaluator{}
