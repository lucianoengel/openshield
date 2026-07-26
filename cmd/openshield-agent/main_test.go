package main

import (
	"os"
	"strings"
	"testing"
)

// TestBuildEvaluatorRequiresASignal: the agent refuses to run answering every exec ALLOW — a no-op
// enforcement is a misconfiguration, not a safe default.
func TestBuildEvaluatorRequiresASignal(t *testing.T) {
	t.Setenv("OPENSHIELD_EXEC_DENY", "")
	t.Setenv("OPENSHIELD_EXEC_ALLOW", "")
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	_, err := buildEvaluator(false)
	if err == nil {
		t.Fatal("buildEvaluator with no signal and no IPC gate succeeded — a no-op exec gate must be refused")
	}
	if !strings.Contains(err.Error(), "OPENSHIELD_EXEC_IPC_SOCKET") {
		t.Errorf("the error should name the IPC gate as one way to configure a signal: %v", err)
	}
}

// TestIPCGateSatisfiesTheSignalRequirement: with the verdict socket configured, the pipeline IS the signal,
// so a static deny-list is no longer required. Without this the IPC-only deployment could not start.
func TestIPCGateSatisfiesTheSignalRequirement(t *testing.T) {
	t.Setenv("OPENSHIELD_EXEC_DENY", "")
	t.Setenv("OPENSHIELD_EXEC_ALLOW", "")
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	ev, err := buildEvaluator(true)
	if err != nil {
		t.Fatalf("buildEvaluator with the IPC gate on: %v", err)
	}
	// And it is genuinely empty — the static evaluator contributes nothing in this mode, so a future
	// change that silently populated it (and thus started blocking from a stale list) would show up here.
	if len(ev.DenyPaths) != 0 || len(ev.DenyBasenames) != 0 || len(ev.AllowPaths) != 0 ||
		len(ev.AllowBasenames) != 0 || ev.BehaviorFloor != 0 {
		t.Errorf("static evaluator is not empty in IPC mode: %+v", ev)
	}
}

// TestStaticModeIsUnchanged: a deny-list alone still configures the gate, exactly as before this change.
func TestStaticModeIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	list := dir + "/deny.txt"
	if err := writeFile(list, "/bin/evil\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_EXEC_DENY", list)
	t.Setenv("OPENSHIELD_EXEC_ALLOW", "")
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	ev, err := buildEvaluator(false)
	if err != nil {
		t.Fatalf("static mode: %v", err)
	}
	if len(ev.DenyPaths) == 0 && len(ev.DenyBasenames) == 0 {
		t.Fatal("the deny-list did not load")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
