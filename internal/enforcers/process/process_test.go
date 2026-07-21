package process_test

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
)

func killDecision() *corev1.Decision {
	return &corev1.Decision{DecisionId: "d", EventId: "e", Action: corev1.Action_ACTION_KILL_PROCESS, Confidence: 0.95}
}

// KILL_PROCESS actually terminates a REAL process (rootless, testable): spawn a long sleep,
// kill it by pid, and confirm it died.
func TestKillEnforcerKillsRealProcess(t *testing.T) {
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a test process: %v", err)
	}
	pid := cmd.Process.Pid

	enf := process.NewKillEnforcer()
	if err := enf.EnforceTarget(context.Background(), killDecision(), strconv.Itoa(pid)); err != nil {
		t.Fatalf("EnforceTarget: %v", err)
	}

	// Wait() reaps it; it should have been SIGKILLed, not exited normally.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("the process exited cleanly — it was not killed")
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill() // cleanup
		t.Fatal("the process was not killed within the timeout")
	}
}

// Fail-safe: the enforcer REFUSES to kill pid ≤ 1 (kernel/init), its own pid, and a
// non-numeric target — a process-killer firing on a bad target is catastrophic.
func TestKillEnforcerFailsSafe(t *testing.T) {
	enf := process.NewKillEnforcer()
	killed := false
	// Replace the kill with a spy via a fresh enforcer is not exported; instead assert the
	// dangerous targets error BEFORE any kill, and that a normal-looking foreign pid would
	// pass the guards (we don't actually kill it — use our own pid to prove the self-guard).
	for _, target := range []string{"1", "0", "-5", "not-a-pid", ""} {
		if err := enf.EnforceTarget(context.Background(), killDecision(), target); err == nil {
			t.Errorf("EnforceTarget(%q) did not error — a dangerous/invalid target must be refused", target)
			killed = true
		}
	}
	// Self-pid is refused too.
	if err := enf.EnforceTarget(context.Background(), killDecision(), strconv.Itoa(os.Getpid())); err == nil {
		t.Error("the enforcer killed (or would kill) its own process — the self-guard failed")
	}
	_ = killed
}

// DENY_EXEC records a deny on the exec controller; a missing controller or empty target
// errors (a deny that goes nowhere would silently allow the execution).
func TestDenyEnforcer(t *testing.T) {
	rec := &recExecCtrl{}
	enf := process.NewDenyEnforcer(rec)
	dec := &corev1.Decision{DecisionId: "d", EventId: "e", Action: corev1.Action_ACTION_DENY_EXEC, Confidence: 0.9}
	if err := enf.EnforceTarget(context.Background(), dec, "exec-77"); err != nil {
		t.Fatal(err)
	}
	if rec.denied != "exec-77" {
		t.Errorf("denied = %q, want exec-77", rec.denied)
	}
	if err := enf.EnforceTarget(context.Background(), dec, ""); err == nil {
		t.Error("empty exec target did not error")
	}
	if err := process.NewDenyEnforcer(nil).EnforceTarget(context.Background(), dec, "x"); err == nil {
		t.Error("a deny with no controller did not error (would silently allow)")
	}
}

type recExecCtrl struct{ denied string }

func (r *recExecCtrl) Deny(execID string) error { r.denied = execID; return nil }
