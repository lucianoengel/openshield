package nips_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/nips"
)

const feedBody = `# operator feed
domain evil.example
ip 203.0.113.9
cidr 198.51.100.0/24
uri /gate.php
`

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestTamperedFeedIsRefusedWithoutParsing is SOAR-5's core property.
//
// The parser is the untrusted-input surface, so a feed that fails verification must never reach it — and
// rejection must be TOTAL. Per-line verification would apply exactly the attacker-chosen subset that
// verified: they would drop the indicators naming their own infrastructure and keep everything else,
// leaving a store that looks healthy while being blind where it matters.
//
// Mutation: parse first and verify after (or skip verification) → the hostile bytes reach the parser and
// a feed is returned → this FAILS.
func TestTamperedFeedIsRefusedWithoutParsing(t *testing.T) {
	pub, priv := keypair(t)
	sig := ed25519.Sign(priv, []byte(feedBody))

	// One byte changed: the attacker removes their own domain from an otherwise-good feed.
	tampered := strings.Replace(feedBody, "domain evil.example\n", "", 1)
	f, err := nips.VerifyAndParse([]byte(tampered), sig, pub, nips.FormatNative)
	if err == nil {
		t.Fatalf("a tampered feed was accepted (%d indicators) — the signature is decorative", f.Size())
	}
	if !errors.Is(err, nips.ErrFeedSignature) {
		t.Errorf("error = %v, want ErrFeedSignature", err)
	}
	if f != nil {
		t.Error("a refused feed returned a parsed result — a partial load is the attacker's best outcome")
	}

	// THE ORDERING, asserted directly. "A bad feed was refused" looks identical whether verification ran
	// first or last — and last means the hostile bytes already went through the parser, which is the
	// surface an attacker is trying to reach. So count parser entries across a refused ingest.
	before := nips.ParseInvocations()
	if _, err := nips.VerifyAndParse([]byte(tampered), sig, pub, nips.FormatNative); err == nil {
		t.Fatal("the tampered feed was accepted on the second attempt")
	}
	if after := nips.ParseInvocations(); after != before {
		t.Errorf("the parser ran %d time(s) on a feed that failed verification — verification is not "+
			"happening FIRST, so hostile bytes reach the parser before anything checks them", after-before)
	}
	// And the parser DOES run for a good feed, so the assertion above is not passing because parsing
	// never happens at all.
	if _, err := nips.VerifyAndParse([]byte(feedBody), sig, pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}
	if nips.ParseInvocations() != before+1 {
		t.Errorf("a VERIFIED feed did not reach the parser — the counter is not measuring what the " +
			"assertion above claims")
	}
}

func TestValidSignatureParsesAndForeignSignatureDoesNot(t *testing.T) {
	pub, priv := keypair(t)
	sig := ed25519.Sign(priv, []byte(feedBody))

	f, err := nips.VerifyAndParse([]byte(feedBody), sig, pub, nips.FormatNative)
	if err != nil {
		t.Fatalf("a validly signed feed was refused: %v", err)
	}
	if f.Size() != 4 {
		t.Errorf("parsed %d indicators, want 4", f.Size())
	}

	// A signature over a DIFFERENT feed must not transfer: otherwise one signed feed authorizes any other.
	otherSig := ed25519.Sign(priv, []byte("domain other.example\n"))
	if _, err := nips.VerifyAndParse([]byte(feedBody), otherSig, pub, nips.FormatNative); !errors.Is(err, nips.ErrFeedSignature) {
		t.Errorf("a signature for a different feed verified: %v", err)
	}
	// A key configured but no signature supplied is a refusal, not a pass-through.
	if _, err := nips.VerifyAndParse([]byte(feedBody), nil, pub, nips.FormatNative); !errors.Is(err, nips.ErrFeedSignature) {
		t.Errorf("a missing signature passed while a key was configured: %v", err)
	}
	// No key configured: unsigned load still works. That is a deliberate CONFIGURATION choice so
	// existing deployments keep running, and it is visible in config rather than implied by code.
	if _, err := nips.VerifyAndParse([]byte(feedBody), nil, nil, nips.FormatNative); err != nil {
		t.Errorf("an unsigned load with no key configured failed: %v", err)
	}
}

// TestFeedRoundTripsThroughItsIndicators is what keeps MATCHING to one implementation: the store persists
// Indicators() and rebuilds with BuildFeed, so the analytical path and the inline engine cannot drift.
//
// Mutation: omit CIDRs (or URIs) from Indicators() → the rebuilt feed misses that hit → this FAILS.
func TestFeedRoundTripsThroughItsIndicators(t *testing.T) {
	original, err := nips.ParseFeed(strings.NewReader(feedBody))
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := nips.BuildFeed(original.Indicators())
	if err != nil {
		t.Fatalf("rebuilding from indicators: %v", err)
	}
	cases := []struct {
		name             string
		host, dstIP, uri string
		want             int
	}{
		{"subdomain of a feed domain", "c2.evil.example", "", "", 1},
		{"unrelated lookalike", "notevil.example", "", "", 0},
		{"exact IP", "", "203.0.113.9", "", 1},
		{"address inside a feed CIDR", "", "198.51.100.7", "", 1},
		{"address outside every CIDR", "", "192.0.2.7", "", 0},
		{"uri substring", "", "", "/x/gate.php?id=1", 1},
	}
	for _, tc := range cases {
		o, r := len(original.Match(tc.host, tc.dstIP, tc.uri)), len(rebuilt.Match(tc.host, tc.dstIP, tc.uri))
		if o != tc.want || r != tc.want {
			t.Errorf("%s: original=%d rebuilt=%d, want %d — a feed that does not round-trip means the "+
				"store and the inline engine match differently", tc.name, o, r, tc.want)
		}
	}
}

// TestCSVFormatIsNamedNotSniffed: CSV parses when asked for, and the format is never inferred from the
// content — letting a crafted file choose its parser is a free surface to close.
func TestCSVFormatIsNamedNotSniffed(t *testing.T) {
	csv := "# a public feed\ndomain,evil.example,seen 2026-01-01\nip,203.0.113.9\ncidr,198.51.100.0/24\n"
	f, err := nips.ParseFormat(strings.NewReader(csv), nips.FormatCSV)
	if err != nil {
		t.Fatalf("csv feed: %v", err)
	}
	if f.Size() != 3 {
		t.Errorf("csv parsed %d indicators, want 3", f.Size())
	}
	if len(f.Match("c2.evil.example", "", "")) != 1 {
		t.Error("csv-loaded domain does not match a subdomain — the shared validation was bypassed")
	}
	// The same bytes under the NATIVE format are an error, not a lucky guess.
	if _, err := nips.ParseFormat(strings.NewReader(csv), nips.FormatNative); err == nil {
		t.Error("csv content parsed as native — the format is being inferred somewhere")
	}
	// An unknown format is refused rather than defaulted.
	if _, err := nips.ParseFormat(strings.NewReader(csv), nips.Format("stix")); err == nil {
		t.Error("an unknown format was accepted")
	}
	// The shared validation applies to CSV too: a degenerate URI indicator is still refused (R34-13).
	if _, err := nips.ParseFormat(strings.NewReader("uri,/\n"), nips.FormatCSV); err == nil {
		t.Error("a degenerate short URI indicator loaded via CSV — the minimum-length guard is not shared")
	}
}
