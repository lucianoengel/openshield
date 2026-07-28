package execmon

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

func verdict(t *testing.T, ev DenyEvaluator, path string) watchdog.Verdict {
	t.Helper()
	v, err := ev.Evaluate(context.Background(), watchdog.PermissionEvent{Path: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return v
}

// TestAllowlistDefaultDeny: with an allowlist configured, a non-allowlisted resolved exec is blocked;
// an allowlisted one runs; an unresolved (empty) path is allowed (cannot verify → availability).
//
// Mutation (drop the default-deny check): the non-allowlisted exec is allowed → this test FAILs.
func TestAllowlistDefaultDeny(t *testing.T) {
	// SCOPED to the monitored directories (D330). Before that bound existed this evaluator refused every
	// executable on the mount — `sudo`, `cat`, `/bin/bash` — leaving a machine recoverable only by a
	// power cycle, since stopping the agent needs exec and logging in needs a shell.
	ev := DenyEvaluator{
		AllowBasenames: map[string]bool{"helper": true},
		AllowPaths:     map[string]bool{"/opt/app/svc": true},
		AllowScope:     []string{"/opt/app", "/usr/bin"},
	}
	if v := verdict(t, ev, "/usr/bin/helper"); v != watchdog.VerdictAllow {
		t.Errorf("allowlisted basename = %v, want Allow", v)
	}
	if v := verdict(t, ev, "/opt/app/svc"); v != watchdog.VerdictAllow {
		t.Errorf("allowlisted path = %v, want Allow", v)
	}
	if v := verdict(t, ev, "/usr/bin/backdoor"); v != watchdog.VerdictBlock {
		t.Errorf("non-allowlisted exec IN SCOPE = %v, want Block (default-deny)", v)
	}
	if v := verdict(t, ev, ""); v != watchdog.VerdictAllow {
		t.Errorf("unresolved path = %v, want Allow (cannot verify)", v)
	}
}

// TestAllowlistDoesNotReachOutsideTheMonitoredDirectories is the fix for the defect that bricked a VM.
//
// The kernel mark is a MOUNT mark — it has to be, because a directory inode mark does not deliver
// FAN_OPEN_EXEC_PERM for files executed inside it — so the evaluator sees every exec on the filesystem.
// An unbounded default-deny therefore refuses the tools needed to undo it.
//
// Mutation (drop the scope check): /usr/bin/sudo and /bin/bash are blocked -> this test FAILs.
func TestAllowlistDoesNotReachOutsideTheMonitoredDirectories(t *testing.T) {
	ev := DenyEvaluator{
		AllowPaths: map[string]bool{"/opt/app/bin/svc": true},
		AllowScope: []string{"/opt/app/bin"},
	}
	// The three that made the machine unrecoverable, plus an ordinary one.
	for _, p := range []string{"/usr/bin/sudo", "/bin/bash", "/usr/bin/cat", "/usr/local/bin/anything"} {
		if v := verdict(t, ev, p); v != watchdog.VerdictAllow {
			t.Errorf("%s = %v, want Allow — it is outside every monitored directory, so it was never in "+
				"the scope the operator declared. Refusing it is what makes the host unrecoverable: "+
				"stopping the agent needs exec, and logging in needs a shell", p, v)
		}
	}
	// And in scope, the allowlist still bites.
	if v := verdict(t, ev, "/opt/app/bin/other"); v != watchdog.VerdictBlock {
		t.Errorf("an unlisted binary INSIDE the monitored directory = %v, want Block — scoping the "+
			"default-deny must not disable it", v)
	}
	if v := verdict(t, ev, "/opt/app/bin/svc"); v != watchdog.VerdictAllow {
		t.Errorf("the allowlisted binary = %v, want Allow", v)
	}
}

// TestAPrefixIsNotAParentDirectory: /opt/application must not be treated as inside /opt/app.
func TestAPrefixIsNotAParentDirectory(t *testing.T) {
	ev := DenyEvaluator{AllowPaths: map[string]bool{}, AllowBasenames: map[string]bool{"x": true}, AllowScope: []string{"/opt/app"}}
	if v := verdict(t, ev, "/opt/application/tool"); v != watchdog.VerdictAllow {
		t.Errorf("/opt/application/tool = %v, want Allow — a shared string prefix is not containment, and "+
			"treating it as such silently widens the blast radius the scope exists to bound", v)
	}
}

// TestTheDenyListKeepsItsReach: an enumerated refusal is bounded by what it names, so it needs no scope.
//
// The asymmetry is deliberate. Narrowing the deny-list too would be the opposite failure — silently
// weakening existing deployments — and harder to notice than the one being fixed.
func TestTheDenyListKeepsItsReach(t *testing.T) {
	ev := DenyEvaluator{
		DenyPaths:  map[string]bool{"/usr/bin/nc": true},
		AllowPaths: map[string]bool{"/opt/app/bin/svc": true},
		AllowScope: []string{"/opt/app/bin"},
	}
	if v := verdict(t, ev, "/usr/bin/nc"); v != watchdog.VerdictBlock {
		t.Errorf("a deny-listed binary outside the monitored directories = %v, want Block — an operator "+
			"who names a binary means it wherever it runs from", v)
	}
}

// TestDenyWinsOverAllow: a binary on BOTH lists is blocked (deny > allow).
//
// Mutation (allowlist checked before deny, allow short-circuits): the binary is allowed → this test FAILs.
func TestDenyWinsOverAllow(t *testing.T) {
	ev := DenyEvaluator{
		AllowBasenames: map[string]bool{"tool": true},
		DenyBasenames:  map[string]bool{"tool": true},
	}
	if v := verdict(t, ev, "/usr/bin/tool"); v != watchdog.VerdictBlock {
		t.Fatalf("a deny-listed AND allow-listed binary = %v, want Block (deny wins)", v)
	}
}

// TestNoAllowlistIsDenyListOnly: without an allowlist, a benign non-denied binary runs (D224 behavior).
func TestNoAllowlistIsDenyListOnly(t *testing.T) {
	ev := DenyEvaluator{DenyBasenames: map[string]bool{"nc": true}}
	if v := verdict(t, ev, "/usr/bin/ls"); v != watchdog.VerdictAllow {
		t.Errorf("no allowlist, benign binary = %v, want Allow", v)
	}
	if v := verdict(t, ev, "/usr/bin/nc"); v != watchdog.VerdictBlock {
		t.Errorf("deny-listed binary = %v, want Block", v)
	}
}
