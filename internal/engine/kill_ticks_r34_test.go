package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// recordingTargetEnforcer captures the exact target string the engine hands the
// enforcer for a KILL — the pid-reuse plumbing (HIPS-7) lives entirely in that
// string, so recording it is what proves the observation-time StartTicks actually
// reaches the enforcer that revalidates process identity.
type recordingTargetEnforcer struct{ target string }

func (*recordingTargetEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_KILL_PROCESS}
}
func (*recordingTargetEnforcer) Enforce(context.Context, *corev1.Decision) error { return nil }
func (r *recordingTargetEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	r.target = target
	return nil
}

var _ core.TargetedEnforcer = (*recordingTargetEnforcer)(nil)

// TestKillTargetCarriesStartTicks (R34-5, test proposal #3): a real
// EVENT_KIND_PROCESS_EXEC that carries StartTicks, flowed through Engine.Process to
// a TargetedEnforcer, must arrive as target == "pid:ticks" — the enforcer needs the
// start-time to spare a recycled pid. This is the plumbing R34-5 found had ZERO
// mutation coverage: zeroing StartTicks at the source or short-circuiting the
// engine's pid:ticks build passed the whole suite green.
//
// Mutation: dropping the ":ticks" suffix in enforceTarget (return bare pid) makes
// the "pid:ticks" assertion FAIL; a StartTicks=0 event falls back to a bare pid,
// asserted by the second case so a source that never captures ticks is also caught.
func TestKillTargetCarriesStartTicks(t *testing.T) {
	kill := stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_KILL_PROCESS}), nil
	})

	// Case 1: an event WITH StartTicks — the enforcer must receive pid:ticks.
	rec := &recordingTargetEnforcer{}
	eng := engine.New(&recordingWorker{}, kill, &recLedger{}, nil, time.Second)
	eng.Enforcers = []core.Enforcer{rec}
	ev := &corev1.Event{
		EventId: "exec-ticks", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid: 4242, StartTicks: 99887766, ExecPath: "/bin/sleep"}},
	}
	if _, err := eng.Process(context.Background(), ev); err != nil {
		t.Fatalf("process event errored: %v", err)
	}
	if rec.target != "4242:99887766" {
		t.Fatalf("kill target = %q, want %q — the observation-time StartTicks did not reach the enforcer (HIPS-7 pid-reuse defense inert)", rec.target, "4242:99887766")
	}

	// Case 2: an event WITHOUT StartTicks (0) — a bare pid, never "pid:0".
	rec2 := &recordingTargetEnforcer{}
	eng2 := engine.New(&recordingWorker{}, kill, &recLedger{}, nil, time.Second)
	eng2.Enforcers = []core.Enforcer{rec2}
	ev2 := &corev1.Event{
		EventId: "exec-noticks", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid: 5150, ExecPath: "/bin/sleep"}},
	}
	if _, err := eng2.Process(context.Background(), ev2); err != nil {
		t.Fatalf("process event (no ticks) errored: %v", err)
	}
	if rec2.target != "5150" {
		t.Fatalf("kill target = %q, want bare pid %q — an unknown start-time must not fabricate a :0 suffix", rec2.target, "5150")
	}
}
