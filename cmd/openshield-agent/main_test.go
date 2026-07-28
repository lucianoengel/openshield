package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/execmon"
)

// TestBuildEvaluatorRequiresASignal: the agent refuses to run answering every exec ALLOW — a no-op
// enforcement is a misconfiguration, not a safe default.
func TestBuildEvaluatorRequiresASignal(t *testing.T) {
	t.Setenv("OPENSHIELD_EXEC_DENY", "")
	t.Setenv("OPENSHIELD_EXEC_ALLOW", "")
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	_, err := buildEvaluator(false, []string{"/opt/watched"})
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

	ev, err := buildEvaluator(true, []string{"/opt/watched"})
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

	ev, err := buildEvaluator(false, []string{"/opt/watched"})
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

// TestAnAllowlistWithoutAScopeIsRefused (D330).
//
// An unbounded default-deny refuses every executable on the MOUNT — the kernel mark is necessarily a
// mount mark — which measured out as refusing `sudo`, `cat` and `/bin/bash` on a live kernel and left a
// machine recoverable only by a power cycle. If nothing bounds it, the agent must refuse to start rather
// than arm it: there is no safe interpretation of "deny everything not listed, everywhere".
func TestAnAllowlistWithoutAScopeIsRefused(t *testing.T) {
	dir := t.TempDir()
	list := dir + "/allow.txt"
	if err := writeFile(list, "/opt/watched/tool\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_EXEC_DENY", "")
	t.Setenv("OPENSHIELD_EXEC_ALLOW", list)
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	if _, err := buildEvaluator(false, nil); err == nil {
		t.Fatal("an allowlist with NO monitored directory to bound it was accepted. Unbounded, it refuses " +
			"every executable on the mount, including the ones needed to stop the agent")
	}
}

// TestAnAllowlistCarriesTheMonitoredDirectoriesAsItsScope.
func TestAnAllowlistCarriesTheMonitoredDirectoriesAsItsScope(t *testing.T) {
	dir := t.TempDir()
	list := dir + "/allow.txt"
	if err := writeFile(list, "/opt/watched/tool\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_EXEC_DENY", "")
	t.Setenv("OPENSHIELD_EXEC_ALLOW", list)
	t.Setenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR", "")

	ev, err := buildEvaluator(false, []string{"/opt/watched"})
	if err != nil {
		t.Fatalf("buildEvaluator: %v", err)
	}
	if len(ev.AllowScope) != 1 || ev.AllowScope[0] != "/opt/watched" {
		t.Errorf("AllowScope = %v, want the monitored directories — without it the default-deny is "+
			"unbounded and the setting is unusable", ev.AllowScope)
	}
}

// TestTheMarkModeFollowsTheGateSemantics (D331).
//
// Per-file marking can only MISS; the mount mark can only WASTE. Those are not symmetric risks in a
// security control, so the narrow mode is used ONLY where the scope is already bounded — the allowlist,
// per D330. Every other signal decides on binaries wherever they run from, and a deployment combining
// them gets the union, which is global.
func TestTheMarkModeFollowsTheGateSemantics(t *testing.T) {
	allow := execmon.DenyEvaluator{AllowPaths: map[string]bool{"/opt/a": true}}
	deny := execmon.DenyEvaluator{DenyBasenames: map[string]bool{"nc": true}}
	both := execmon.DenyEvaluator{
		AllowPaths:    map[string]bool{"/opt/a": true},
		DenyBasenames: map[string]bool{"nc": true},
	}
	floor := execmon.DenyEvaluator{AllowPaths: map[string]bool{"/opt/a": true}, BehaviorFloor: 0.9}

	for _, c := range []struct {
		name string
		ev   execmon.DenyEvaluator
		ipc  bool
		want execmon.MarkMode
		why  string
	}{
		{"allowlist alone", allow, false, execmon.MarkPerFile,
			"its reach is the monitored directories, so an exec elsewhere is out of scope by definition"},
		{"deny-list alone", deny, false, execmon.MarkMount,
			"a deny-list names binaries to refuse WHEREVER they run from"},
		{"allowlist + deny-list", both, false, execmon.MarkMount,
			"the union of a scoped and a global signal is global"},
		{"allowlist + behavioural floor", floor, false, execmon.MarkMount,
			"the floor decides on whatever it is shown"},
		{"allowlist + IPC gate", allow, true, execmon.MarkMount,
			"a pipeline verdict is not bounded by the allowlist's scope"},
	} {
		if got := markModeFor(c.ev, c.ipc); got != c.want {
			t.Errorf("%s: mark = %v, want %v — %s", c.name, got, c.want, c.why)
		}
	}
}
