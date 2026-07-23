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
	ev := DenyEvaluator{AllowBasenames: map[string]bool{"helper": true}, AllowPaths: map[string]bool{"/opt/app/svc": true}}
	if v := verdict(t, ev, "/usr/bin/helper"); v != watchdog.VerdictAllow {
		t.Errorf("allowlisted basename = %v, want Allow", v)
	}
	if v := verdict(t, ev, "/opt/app/svc"); v != watchdog.VerdictAllow {
		t.Errorf("allowlisted path = %v, want Allow", v)
	}
	if v := verdict(t, ev, "/tmp/backdoor"); v != watchdog.VerdictBlock {
		t.Errorf("non-allowlisted exec = %v, want Block (default-deny)", v)
	}
	if v := verdict(t, ev, ""); v != watchdog.VerdictAllow {
		t.Errorf("unresolved path = %v, want Allow (cannot verify)", v)
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
