package controlplane

import (
	"sort"
	"testing"
)

// newlyOverdue returns only agents newly overdue vs the previous set, and carries
// forward exactly the current overdue set (a recovered agent drops out).
func TestNewlyOverdueDedups(t *testing.T) {
	// First round: a and b are overdue; both are fresh.
	fresh, next := newlyOverdue(map[string]bool{}, []string{"a", "b"})
	sort.Strings(fresh)
	if len(fresh) != 2 || fresh[0] != "a" || fresh[1] != "b" {
		t.Fatalf("first round fresh = %v, want [a b]", fresh)
	}

	// Second round: a and b still overdue (already notified) → none fresh; c new.
	fresh, next = newlyOverdue(next, []string{"a", "b", "c"})
	if len(fresh) != 1 || fresh[0] != "c" {
		t.Fatalf("second round fresh = %v, want [c]", fresh)
	}

	// Third round: a recovered (not overdue) — it drops from the set, so if it goes
	// overdue again it is fresh once more.
	_, next = newlyOverdue(next, []string{"b", "c"})
	if next["a"] {
		t.Error("a recovered but stayed in the notified set — it could never alert again")
	}
	fresh, _ = newlyOverdue(next, []string{"a", "b", "c"})
	if len(fresh) != 1 || fresh[0] != "a" {
		t.Fatalf("after recovery, fresh = %v, want [a] (it can alert again)", fresh)
	}
}
