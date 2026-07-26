package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// PLAT-9: the ENDPOINT half of the emergency disable.
//
// A kill switch honoured by the gateway and forgotten by the engine is worse than none — the operator
// believes enforcement stopped, and it did not. This test is the half a gateway-only implementation
// misses.
//
// Mutation: consult the switch only in the gateway (remove the engine's guard) → the engine still kills
// the process → FAILS.
func TestEngineHonoursTheEmergencyDisable(t *testing.T) {
	kill := stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_KILL_PROCESS}), nil
	})
	newEvent := func(id string) *corev1.Event {
		return &corev1.Event{
			EventId: id, Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind:   corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
			Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{Pid: 4242, ExecPath: "/bin/sleep"}},
		}
	}

	rec := &recordingTargetEnforcer{}
	ledger := &recLedger{}
	ks := core.NewKillSwitch(nil)
	eng := engine.New(&recordingWorker{}, kill, ledger, nil, time.Second)
	eng.Enforcers = []core.Enforcer{rec}
	eng.KillSwitch = ks

	// Engaged: the enforcer must not be reached.
	ks.Engage("incident 41", "operator:alice")
	if _, err := eng.Process(context.Background(), newEvent("exec-suppressed")); err != nil {
		t.Fatalf("processing errored: %v", err)
	}
	if rec.target != "" {
		t.Fatalf("the enforcer was invoked (target %q) while the emergency disable was ENGAGED — an "+
			"operator who stopped enforcement is still killing processes", rec.target)
	}
	if got := ks.Suppressions.Load(); got != 1 {
		t.Errorf("suppressions = %d, want 1", got)
	}

	// STOP ACTING, KEEP SEEING: the pipeline still ran and the decision is still recorded. A kill switch
	// that also stopped the trail would be a blindfold over exactly the period an operator must
	// reconstruct.
	if len(ledger.entries) == 0 {
		t.Error("nothing was recorded while enforcement was suppressed — the record of what WOULD have " +
			"been enforced is the whole point of stopping at the enforcer rather than earlier")
	}

	// Disengaged: enforcement resumes.
	ks.Disengage("operator:alice")
	if _, err := eng.Process(context.Background(), newEvent("exec-enforced")); err != nil {
		t.Fatalf("processing errored: %v", err)
	}
	if rec.target == "" {
		t.Error("enforcement did not resume after the switch was disengaged")
	}
}
