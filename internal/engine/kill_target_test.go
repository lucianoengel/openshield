package engine_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
	"github.com/lucianoengel/openshield/internal/engine"
)

func procEvent(id string, pid int) *corev1.Event {
	return &corev1.Event{
		EventId: id, Purpose: corev1.Purpose_PURPOSE_DLP, Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid: int32(pid), ExecPath: "/bin/sleep"}},
	}
}

// HIPS-5: a KILL_PROCESS decision on a process event terminates the REAL process named by the
// event's pid — the enforce path now selects the pid target by event kind, so the pid-based
// enforcer no longer receives an empty (filesystem) target and self-refuses. Real adversary: an
// actual child process is spawned and must be dead after enforcement.
func TestProcessEventKillsRealProcess(t *testing.T) {
	cmd := exec.Command("sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn target: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Process.Kill() }() // belt-and-suspenders if the test fails before the kill

	// A policy that decides KILL_PROCESS for a process event.
	kill := stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_KILL_PROCESS}), nil
	})
	eng := engine.New(&recordingWorker{}, kill, &recLedger{}, nil, time.Second)
	eng.Enforcers = []core.Enforcer{process.NewKillEnforcer()}

	if _, err := eng.Process(context.Background(), procEvent("p1", pid)); err != nil {
		t.Fatalf("process event errored: %v", err)
	}

	// The real process must be dead within a short window.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done: // reaped — it was killed
	case <-time.After(3 * time.Second):
		t.Fatalf("the target process (pid %d) is still alive — the KILL enforcer did not receive its pid", pid)
	}

	// Self-protection: a KILL decision targeting the ENGINE's own pid is refused (audited failure),
	// never suicide. Enforcement records the failure but Process does not error.
	self := &recLedger{}
	engSelf := engine.New(&recordingWorker{}, kill, self, nil, time.Second)
	engSelf.Enforcers = []core.Enforcer{process.NewKillEnforcer()}
	if _, err := engSelf.Process(context.Background(), procEvent("p2", os.Getpid())); err != nil {
		t.Fatalf("self-targeted process event errored: %v", err)
	}
	// We are still running (the assertion itself proves we did not kill ourselves), and the
	// enforcement outcome should be recorded as failed.
	sawFail := false
	for _, e := range self.entries {
		if e.OutcomeKind == "enforcement-failed" {
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("a self-targeted KILL was not recorded as a failed enforcement (self-protection must be audited)")
	}
}
