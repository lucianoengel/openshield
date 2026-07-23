package watchdog_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func execEval(action corev1.Action, err error) watchdog.ExecEvaluator {
	return watchdog.ExecEvaluator{Decide: func(context.Context, watchdog.PermissionEvent) (corev1.Action, error) {
		return action, err
	}}
}

// TestExecEvaluatorVerdicts (HIPS-3): only ACTION_DENY_EXEC yields VerdictBlock; every other action
// allows the exec; a decider error propagates (so the watchdog fail-opens).
//
// Mutation: if Evaluate returned Allow for DENY_EXEC, the deny case FAILs; if it swallowed the error,
// the error case FAILs.
func TestExecEvaluatorVerdicts(t *testing.T) {
	ctx := context.Background()
	// DENY_EXEC → Block.
	if v, err := execEval(corev1.Action_ACTION_DENY_EXEC, nil).Evaluate(ctx, watchdog.PermissionEvent{}); err != nil || v != watchdog.VerdictBlock {
		t.Fatalf("DENY_EXEC → (%v,%v), want (Block,nil)", v, err)
	}
	// Everything else → Allow.
	for _, a := range []corev1.Action{
		corev1.Action_ACTION_ALLOW, corev1.Action_ACTION_ALERT,
		corev1.Action_ACTION_KILL_PROCESS, corev1.Action_ACTION_BLOCK,
	} {
		if v, err := execEval(a, nil).Evaluate(ctx, watchdog.PermissionEvent{}); err != nil || v != watchdog.VerdictAllow {
			t.Errorf("%v → (%v,%v), want (Allow,nil)", a, v, err)
		}
	}
	// A decider error propagates (watchdog fail-opens on it).
	wantErr := errors.New("boom")
	if _, err := execEval(corev1.Action_ACTION_DENY_EXEC, wantErr).Evaluate(ctx, watchdog.PermissionEvent{}); !errors.Is(err, wantErr) {
		t.Fatalf("a decider error was not propagated (got %v) — the watchdog could not fail-open on it", err)
	}
}

// TestExecEvaluatorWithWatchdog (HIPS-3): composed with the real watchdog, a DENY_EXEC decision answers
// the kernel DENY, an ALLOW answers ALLOW, and a slow/failing decider FAILS OPEN (answers Allow) —
// inline prevention never hangs an exec.
func TestExecEvaluatorWithWatchdog(t *testing.T) {
	ctx := context.Background()
	newWD := func(ev watchdog.Evaluator, r watchdog.Responder) *watchdog.Watchdog {
		return &watchdog.Watchdog{SelfPID: 1, Budget: 50 * time.Millisecond, Responder: r, Evaluator: ev,
			Audit: func(context.Context, watchdog.PermissionEvent, core.Severity, string) error { return nil }}
	}
	e := watchdog.PermissionEvent{PID: 4242, Path: "/tmp/evil"}

	// DENY_EXEC → the kernel is answered DENY.
	rDeny := &recordingResponder{}
	if err := newWD(execEval(corev1.Action_ACTION_DENY_EXEC, nil), rDeny).Handle(ctx, e); err != nil {
		t.Fatal(err)
	}
	if a, d, n := rDeny.counts(); d != 1 || a != 0 || n != 1 {
		t.Fatalf("DENY_EXEC answers: allows=%d denies=%d total=%d, want exactly one DENY", a, d, n)
	}

	// ALLOW → the kernel is answered ALLOW.
	rAllow := &recordingResponder{}
	if err := newWD(execEval(corev1.Action_ACTION_ALLOW, nil), rAllow).Handle(ctx, e); err != nil {
		t.Fatal(err)
	}
	if a, d, _ := rAllow.counts(); a != 1 || d != 0 {
		t.Fatalf("ALLOW answers: allows=%d denies=%d, want exactly one ALLOW", a, d)
	}

	// A decider slower than the budget → FAIL-OPEN (answered ALLOW), never a hang or a spurious block.
	slow := watchdog.ExecEvaluator{Decide: func(dctx context.Context, _ watchdog.PermissionEvent) (corev1.Action, error) {
		select {
		case <-time.After(2 * time.Second):
			return corev1.Action_ACTION_DENY_EXEC, nil // would deny, but the budget elapses first
		case <-dctx.Done():
			return corev1.Action_ACTION_ALLOW, dctx.Err()
		}
	}}
	rSlow := &recordingResponder{}
	if err := newWD(slow, rSlow).Handle(ctx, e); err != nil {
		t.Fatal(err)
	}
	if a, d, _ := rSlow.counts(); a != 1 || d != 0 {
		t.Fatalf("a slow exec decision did not fail-open: allows=%d denies=%d, want one ALLOW (never hang/block)", a, d)
	}
}
