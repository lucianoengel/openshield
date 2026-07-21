package core_test

import (
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestPseudonymousAndPurposePinned locks the two invariants the legal basis of
// the system rests on (D23, D20): the boundary subject identity is pseudonymous,
// and every event carries a purpose. An unpinned invariant rots silently, and
// these two would rot into a compliance failure.
func TestPseudonymousAndPurposePinned(t *testing.T) {
	// D23: the Subject's field set is EXACTLY the pseudonymous id. Adding a raw
	// identity (name, email, uid) here — the exact regression that would break
	// pseudonymisation — fails this test.
	got := structFieldNames(corev1.Subject{})
	want := []string{"PseudonymousId"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Subject fields = %v, want exactly %v — the boundary subject must be "+
			"pseudonymous and carry no raw identity (D23)", got, want)
	}

	// D20: an event carries a purpose, and the unspecified zero is not a valid
	// production purpose.
	e := &corev1.Event{Purpose: corev1.Purpose_PURPOSE_DLP}
	if e.GetPurpose() == corev1.Purpose_PURPOSE_UNSPECIFIED {
		t.Error("event purpose is unset — every event must be tagged with a purpose (D20)")
	}
}
