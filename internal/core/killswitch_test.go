package core_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// PLAT-9 increment 1: the emergency disable.

func dec(a corev1.Action) *corev1.Decision { return &corev1.Decision{Action: a} }

// TestOnlyEnforcingActionsAreSuppressed, and only while engaged.
func TestOnlyEnforcingActionsAreSuppressed(t *testing.T) {
	k := core.NewKillSwitch(nil)

	// Disengaged: nothing is suppressed. Absence is never engagement.
	if s, _ := k.SuppressEnforcement(dec(corev1.Action_ACTION_BLOCK)); s {
		t.Fatal("a disengaged switch suppressed enforcement — the switch must be AFFIRMATIVELY engaged")
	}

	k.Engage("incident 41", "operator:alice")
	for _, a := range []corev1.Action{
		corev1.Action_ACTION_BLOCK, corev1.Action_ACTION_QUARANTINE_LOCAL,
		corev1.Action_ACTION_ENCRYPT_LOCAL, corev1.Action_ACTION_KILL_PROCESS,
		corev1.Action_ACTION_DENY_EXEC,
	} {
		s, reason := k.SuppressEnforcement(dec(a))
		if !s {
			t.Errorf("%v was NOT suppressed while the switch is engaged", a)
		}
		if reason != "incident 41" {
			t.Errorf("suppression reason = %q, want the reason the switch is engaged — an operator "+
				"needs to know WHY, not just that", reason)
		}
	}
	// An alert-only decision enforces nothing, so there is nothing to suppress; counting it would
	// inflate the number an operator uses to ask what was not blocked.
	for _, a := range []corev1.Action{corev1.Action_ACTION_ALLOW, corev1.Action_ACTION_ALERT} {
		if s, _ := k.SuppressEnforcement(dec(a)); s {
			t.Errorf("%v was suppressed — it never enforced anything", a)
		}
	}
	if got := k.Suppressions.Load(); got != 5 {
		t.Errorf("suppressions = %d, want 5 — 'the switch is on' cannot answer 'what did we not block "+
			"during those forty minutes'", got)
	}

	// Disengaging restores enforcement.
	k.Disengage("operator:alice")
	if s, _ := k.SuppressEnforcement(dec(corev1.Action_ACTION_BLOCK)); s {
		t.Error("enforcement was still suppressed after the switch was disengaged")
	}
}

// TestEngagingIsRecorded — a silent kill switch is indistinguishable from a product that stopped working.
func TestEngagingIsRecorded(t *testing.T) {
	type change struct {
		engaged        bool
		reason, source string
	}
	var seen []change
	k := core.NewKillSwitch(func(engaged bool, reason, source string) {
		seen = append(seen, change{engaged, reason, source})
	})
	k.Engage("incident 41", "operator:alice")
	k.Engage("incident 41", "operator:alice") // idempotent: no second notification
	k.Disengage("operator:bob")
	if len(seen) != 2 {
		t.Fatalf("recorded %d change(s) %+v, want 2 (engage, disengage)", len(seen), seen)
	}
	if !seen[0].engaged || seen[0].reason != "incident 41" || seen[0].source != "operator:alice" {
		t.Errorf("engagement = %+v, want the reason and the source recorded", seen[0])
	}
	if seen[1].engaged || seen[1].source != "operator:bob" {
		t.Errorf("disengagement = %+v", seen[1])
	}
}

// TestTheSwitchFailsTowardEnforcing is the asymmetry that matters.
//
// The watchdog fails OPEN (D17) because a dead DLP that blocks everything gets uninstalled. This one
// fails the other way: a read error that silently disabled enforcement would let a corrupted file or a
// permissions change quietly turn the product off across a fleet — an availability failure converted into
// a security failure.
//
// Mutation: treat a read error as engaged → FAILS.
func TestTheSwitchFailsTowardEnforcing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "EMERGENCY_DISABLE")
	k := core.NewKillSwitch(nil)
	stop := make(chan struct{})
	defer close(stop)
	go k.WatchBreakGlass(stop, path, 10*time.Millisecond)

	// ABSENCE IS NOT ENGAGEMENT.
	time.Sleep(50 * time.Millisecond)
	if engaged, _ := k.Engaged(); engaged {
		t.Fatal("a missing break-glass file engaged the switch — absence is the normal state and cannot " +
			"be allowed to mean 'stop enforcing'")
	}

	// AN EMPTY FILE STILL ENGAGES, with a placeholder reason. Asserted explicitly because it is the state
	// os.WriteFile passes through — it truncates, then writes — so a poll landing between the two sees
	// exactly this. Failing toward engaging is correct: an empty break-glass file is still an operator
	// saying stop.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { e, _ := k.Engaged(); return e })
	if _, reason := k.Engaged(); reason != "break-glass file" {
		t.Errorf("an empty break-glass file gave reason %q, want the placeholder", reason)
	}

	// Present with contents: engaged, carrying the operator's reason.
	if err := os.WriteFile(path, []byte("incident 41: gateway blocking prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// THE REASON MUST UPDATE ON AN ALREADY-ENGAGED SWITCH, which is what the empty-file step above sets up
	// and what used to be impossible: `set` returned early whenever the engaged state was unchanged, so the
	// reason froze at whatever it was when the switch first engaged.
	//
	// That is exactly the sequence `echo "..." > break-glass` produces — os.WriteFile truncates, then
	// writes — so an operator's justification was DISCARDED whenever a poll landed on the empty moment. It
	// surfaced as an intermittent CI failure under GOARCH=386, which had nothing to do with the
	// architecture: a loaded runner simply widens the window. The test was right and the product was wrong.
	waitUntil(t, func() bool { _, r := k.Engaged(); return r == "incident 41: gateway blocking prod" })
	if engaged, _ := k.Engaged(); !engaged {
		t.Error("the reason arrived but the switch is not engaged")
	}

	// UNREADABLE: the switch is left AS IT IS and the failure is counted. Treating this as "engaged"
	// would let a permissions change disable the product; as "disengaged" would silently re-enable
	// enforcement an operator had stopped.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skip("cannot make the file unreadable in this environment")
	}
	before := k.ReadFailures()
	waitUntil(t, func() bool { return k.ReadFailures() > before })
	if engaged, _ := k.Engaged(); !engaged {
		t.Error("an unreadable file DISENGAGED the switch — it must be left as it is")
	}
	_ = os.Chmod(path, 0o600)

	// Removed: enforcement resumes.
	os.Remove(path)
	waitUntil(t, func() bool { e, _ := k.Engaged(); return !e })
}

// TestUnreadableSourceOnAFreshSwitchLeavesEnforcementOn — the case that matters most: the switch has
// never been engaged and its source cannot be read. Enforcement must CONTINUE.
func TestUnreadableSourceOnAFreshSwitchLeavesEnforcementOn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "EMERGENCY_DISABLE")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(path); err == nil {
		t.Skipf("this environment can read a 0000 file (%q); the case is untestable here", body)
	}
	k := core.NewKillSwitch(nil)
	stop := make(chan struct{})
	defer close(stop)
	go k.WatchBreakGlass(stop, path, 10*time.Millisecond)
	waitUntil(t, func() bool { return k.ReadFailures() > 0 })
	if engaged, _ := k.Engaged(); engaged {
		t.Error("an UNREADABLE source engaged the switch — a corrupted file or a permissions change " +
			"would then quietly turn enforcement off across a fleet")
	}
	if s, _ := k.SuppressEnforcement(dec(corev1.Action_ACTION_BLOCK)); s {
		t.Error("enforcement was suppressed because the switch's state could not be read")
	}
}

// TestANilSwitchEnforcesNormally — a component never given a switch must enforce, not silently do nothing.
func TestANilSwitchEnforcesNormally(t *testing.T) {
	var k *core.KillSwitch
	if s, _ := k.SuppressEnforcement(dec(corev1.Action_ACTION_BLOCK)); s {
		t.Error("a nil switch suppressed enforcement")
	}
	if engaged, _ := k.Engaged(); engaged {
		t.Error("a nil switch reported itself engaged")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
