package execguard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/execguard"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// fakeProcessor records the event it was handed and returns a configured decision/error, so the test
// verifies the adapter's translation (permission event → EVENT_KIND_PROCESS_EXEC → action) without a
// full engine — the engine's own tests cover Process; this covers the wiring.
type fakeProcessor struct {
	got    *corev1.Event
	action corev1.Action
	err    error
}

func (f *fakeProcessor) Process(_ context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	f.got = ev
	if f.err != nil {
		return nil, f.err
	}
	return &corev1.Decision{Action: f.action}, nil
}

// TestDeciderBuildsExecEventAndMapsAction (HIPS-3): the decider turns a permission event into an
// EVENT_KIND_PROCESS_EXEC event carrying the pid and binary path, runs the engine, and returns the
// decision's action for the ExecEvaluator.
//
// Mutation: if the decider set the wrong Kind, the kind assert FAILs; if it dropped the pid/path, the
// subject asserts FAIL; if it returned a fixed action instead of the decision's, the action assert FAILs.
func TestDeciderBuildsExecEventAndMapsAction(t *testing.T) {
	fp := &fakeProcessor{action: corev1.Action_ACTION_DENY_EXEC}
	decide := execguard.Decider(fp)

	action, err := decide(context.Background(), watchdog.PermissionEvent{PID: 4242, Path: "/tmp/evil"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != corev1.Action_ACTION_DENY_EXEC {
		t.Fatalf("action = %v, want DENY_EXEC (the decision's action must be returned)", action)
	}
	if fp.got == nil {
		t.Fatal("engine.Process was never called")
	}
	if fp.got.GetKind() != corev1.EventKind_EVENT_KIND_PROCESS_EXEC {
		t.Fatalf("event kind = %v, want EVENT_KIND_PROCESS_EXEC", fp.got.GetKind())
	}
	if p := fp.got.GetProcess(); p == nil || p.GetPid() != 4242 || p.GetExecPath() != "/tmp/evil" {
		t.Fatalf("process subject = %+v, want pid 4242 path /tmp/evil (the permission event's pid/path)", fp.got.GetProcess())
	}
}

// TestDeciderPropagatesEngineError (HIPS-3): a Process error is returned so the watchdog fail-opens
// (never hang or spuriously block an exec on an evaluation crash).
//
// Mutation: if the decider swallowed the error (returned nil), this FAILs.
func TestDeciderPropagatesEngineError(t *testing.T) {
	wantErr := errors.New("pipeline down")
	decide := execguard.Decider(&fakeProcessor{err: wantErr})

	action, err := decide(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/ls"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want it propagated (the watchdog fail-opens on it)", err)
	}
	if action != corev1.Action_ACTION_UNSPECIFIED {
		t.Fatalf("action on error = %v, want UNSPECIFIED (no action decided)", action)
	}
}

// TestDeciderMapsNonDenyActions (HIPS-3): the decider returns whatever action the engine decided —
// ALLOW/ALERT/KILL flow through unchanged (the ExecEvaluator, not the decider, decides which action
// blocks the exec).
func TestDeciderMapsNonDenyActions(t *testing.T) {
	for _, a := range []corev1.Action{
		corev1.Action_ACTION_ALLOW, corev1.Action_ACTION_ALERT, corev1.Action_ACTION_KILL_PROCESS,
	} {
		got, err := execguard.Decider(&fakeProcessor{action: a})(context.Background(), watchdog.PermissionEvent{})
		if err != nil || got != a {
			t.Errorf("action %v → (%v,%v), want (%v,nil)", a, got, err, a)
		}
	}
}
