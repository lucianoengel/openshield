package policy

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The data-plane lattice is total and ordered most-restrictive-last (ADR-5).
func TestDataRankOrdering(t *testing.T) {
	order := []corev1.Action{
		corev1.Action_ACTION_ALLOW,
		corev1.Action_ACTION_ALERT,
		corev1.Action_ACTION_REDIRECT,
		corev1.Action_ACTION_ENCRYPT_LOCAL,
		corev1.Action_ACTION_QUARANTINE_LOCAL,
		corev1.Action_ACTION_BLOCK,
	}
	prev := -1
	for _, a := range order {
		r, ok := dataRank(a)
		if !ok {
			t.Fatalf("%v is not ranked as a data verb", a)
		}
		if r <= prev {
			t.Errorf("%v rank %d not strictly greater than the previous %d — lattice order broken", a, r, prev)
		}
		prev = r
	}
	// Process verbs are OFF the data lattice.
	for _, a := range []corev1.Action{corev1.Action_ACTION_DENY_EXEC, corev1.Action_ACTION_KILL_PROCESS} {
		if _, ok := dataRank(a); ok {
			t.Errorf("%v must not be a data-lattice verb (ADR-5)", a)
		}
	}
}

// The winner is the most-restrictive data candidate across modules.
func TestSelectWinnerMostRestrictive(t *testing.T) {
	d := func(a corev1.Action) candidate { return candidate{name: "m", action: a} }
	cases := []struct {
		in   []candidate
		want corev1.Action
	}{
		{[]candidate{d(corev1.Action_ACTION_ALLOW), d(corev1.Action_ACTION_ALERT), d(corev1.Action_ACTION_BLOCK)}, corev1.Action_ACTION_BLOCK},
		{[]candidate{d(corev1.Action_ACTION_ENCRYPT_LOCAL), d(corev1.Action_ACTION_QUARANTINE_LOCAL)}, corev1.Action_ACTION_QUARANTINE_LOCAL},
		{[]candidate{d(corev1.Action_ACTION_ALLOW), d(corev1.Action_ACTION_ALERT)}, corev1.Action_ACTION_ALERT},
		{[]candidate{d(corev1.Action_ACTION_ALLOW)}, corev1.Action_ACTION_ALLOW},
	}
	for _, c := range cases {
		w, err := selectWinner(c.in)
		if err != nil {
			t.Fatalf("selectWinner(%v): %v", c.in, err)
		}
		if w.action != c.want {
			t.Errorf("selectWinner(%v) = %v, want %v (most-restrictive-wins)", c.in, w.action, c.want)
		}
	}
}

// A compliance PACK that yields a process-control verb is rejected — a pack must never
// silently escalate to killing/denying a process (ADR-5). The same verb from the
// default/operator axis is allowed and takes precedence over data verbs.
func TestSelectWinnerProcessVerbGuardAndPrecedence(t *testing.T) {
	// A pack emitting KILL_PROCESS → hard error.
	_, err := selectWinner([]candidate{
		{name: "default", action: corev1.Action_ACTION_ALERT},
		{name: "pci", isPack: true, action: corev1.Action_ACTION_KILL_PROCESS},
	})
	if err == nil {
		t.Error("a compliance pack yielding KILL_PROCESS was accepted — the pack-cannot-escalate guard is broken")
	}

	// The default/operator (isPack=false) may emit a process verb; it wins over data candidates.
	w, err := selectWinner([]candidate{
		{name: "default", action: corev1.Action_ACTION_ALERT},
		{name: "pci", isPack: true, action: corev1.Action_ACTION_ALLOW},
		{name: "custom", action: corev1.Action_ACTION_KILL_PROCESS},
	})
	if err != nil {
		t.Fatalf("operator KILL_PROCESS rejected: %v", err)
	}
	if w.action != corev1.Action_ACTION_KILL_PROCESS {
		t.Errorf("winner = %v, want KILL_PROCESS (process verb takes precedence over a pack's ALLOW)", w.action)
	}
}
