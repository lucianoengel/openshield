package pseudonym_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// The pseudonym is a persisted key shape: enrollment rosters, stored posture, and the
// proxy's cert-derived subject all rely on it being stable. A change to the domain
// separator or the truncation length would silently re-key every existing subject and
// break the posture chain again — so the exact output is pinned here.
func TestOfIsPinned(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"agent-007", "sub_b8df06d196c3cf6a8780bdc0"},
		{"", "sub_eec17ffe09168512207f381f"},
	} {
		if got := pseudonym.Of(tc.in); got != tc.want {
			t.Errorf("Of(%q) = %q, want %q — the canonical derivation changed; every stored "+
				"pseudonym and roster key would silently re-key", tc.in, got, tc.want)
		}
	}
}

// Same input -> same subject (the property the whole chain depends on) and the "sub_"
// marker is present so a raw identity can never be mistaken for a pseudonym.
func TestOfDeterministicAndMarked(t *testing.T) {
	const id = "some-agent-identity"
	a, b := pseudonym.Of(id), pseudonym.Of(id)
	if a != b {
		t.Fatalf("Of is not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "sub_") {
		t.Errorf("Of(%q) = %q, missing the sub_ marker", id, a)
	}
	if a == pseudonym.Of("some-agent-identityX") {
		t.Error("distinct identities collided")
	}
}
