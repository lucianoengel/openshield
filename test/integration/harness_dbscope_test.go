//go:build integration

package integration

import (
	"strings"
	"testing"
)

// THE COLLISION THIS FIXES REACHED CI (D478).
//
// Two tests both called DSNFor(t, "endpoint"). Under `-run` each passed; in the full suite the second
// failed with `database "endpoint" already exists`, because the Postgres container is shared. The old
// convention was "pick a name nobody else used" — knowledge every new test has to have, enforced by
// nothing, and silent until someone runs everything at once.
//
// These are unit assertions on the naming, not on the database: the collision itself is proven gone by
// the suite passing, and a test that created databases to check names would be slower and no clearer.

func TestTwoTestsAskingForTheSameDatabaseGetDifferentOnes(t *testing.T) {
	a := scopedDBName("TestAFleetWideDisableReachesAGatewayAndStopsEnforcement", "endpoint")
	b := scopedDBName("TestTheRealEngineAttestsWithARealTPMAndIsAdmitted", "endpoint")
	if a == b {
		t.Fatalf("two tests asking for %q got the same database %q — this is the exact failure that "+
			"reached CI, and it is invisible under -run", "endpoint", a)
	}
	for _, n := range []string{a, b} {
		if !strings.HasSuffix(n, "_endpoint") {
			t.Errorf("%q dropped the caller's own label, which is what makes a stray database "+
				"identifiable when a test leaks one", n)
		}
	}
}

// TestALongTestNameStillYieldsAUsableIdentifier — Postgres truncates at 63 bytes, and a truncation that
// produced an invalid or colliding identifier would trade one silent failure for another.
func TestALongTestNameStillYieldsAUsableIdentifier(t *testing.T) {
	long := "TestThe" + strings.Repeat("VeryLongDescriptiveNameSegment", 4)
	got := scopedDBName(long, "endpoint")
	if len(got) > 63 {
		t.Errorf("identifier is %d bytes, over Postgres's 63-byte limit: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "_endpoint") {
		t.Errorf("truncation dropped the caller's label: %q", got)
	}
	// TRUNCATION KEEPS THE TAIL. These names share a 34-character prefix, which is precisely where
	// head-truncation would make them identical again.
	other := scopedDBName(long+"Two", "endpoint")
	if got == other {
		t.Errorf("two long names sharing a prefix truncated to the same identifier %q — cutting from "+
			"the front reintroduces the collision this exists to remove", got)
	}
}

// TestTheIdentifierIsAlwaysValid — an unquoted-safe, lower-case identifier, whatever the test is called.
func TestTheIdentifierIsAlwaysValid(t *testing.T) {
	got := scopedDBName("TestThings/with subtests-and.punctuation", "my db")
	for _, r := range got {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
		if !ok {
			t.Fatalf("identifier %q contains %q, which needs quoting to be safe", got, r)
		}
	}
}
