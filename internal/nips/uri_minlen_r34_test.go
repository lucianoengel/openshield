package nips

import (
	"strings"
	"testing"
)

// TestParseFeedRejectsShortURI (R34-13): a URI IOC is substring-matched, so a degenerate short token
// like "/" would flag nearly every HTTP flow. Such an indicator must be rejected at parse time — a
// feed typo cannot silently turn the IPS into "block everything".
//
// Mutation: removing the min-length check in ParseFeed accepts "uri /", after which matchURI("/x")
// matches — the rejection assertion FAILS.
func TestParseFeedRejectsShortURI(t *testing.T) {
	for _, bad := range []string{"uri /", "uri ab", "uri x"} {
		if _, err := ParseFeed(strings.NewReader(bad + "\n")); err == nil {
			t.Errorf("ParseFeed accepted a too-short URI IOC %q — it would match nearly every flow", bad)
		}
	}
	// A discriminating URI is still accepted and matches only its own path.
	f := mustFeed(t, "uri /c2/beacon\n")
	if f.matchURI("/c2/beacon/x") == "" {
		t.Error("a valid URI IOC did not match a path containing it")
	}
	if f.matchURI("/harmless") != "" {
		t.Error("a valid URI IOC spuriously matched an unrelated path")
	}
}
