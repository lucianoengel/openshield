package gateway_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/nips"
)

// NIPS-9 through the whole pipeline: a listed CLIENT fingerprint blocks a flow whose DESTINATION is
// listed nowhere.
//
// That is the entire reason JA3 is here. Domain, IP and URI intel all describe where a flow is going, and
// a family that rotates domains daily, registers a name nobody has seen, or encrypts the SNI defeats all
// three at once. The client stack is the part that does not change between campaigns.

const badJA3 = "e7d705a3286e19ea42f587b344ee6865" // a fingerprint an operator listed

// TestAListedClientFingerprintBlocksAFlowToAnUnlistedDestination is the headline.
//
// Mutation (drop the MatchJA3 call from threatClassifyStage, or stop populating Ja3 on the event): the
// flow is allowed → FAIL. The destination is deliberately clean, so nothing else can produce the block.
func TestAListedClientFingerprintBlocksAFlowToAnUnlistedDestination(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "domain c2.evil.com\nja3 "+badJA3+"\n"))

	r := &gateway.Request{
		FlowID: "ja3-1", SrcIP: "10.0.0.5", DstIP: "93.184.216.34", Protocol: "tcp",
		// A destination on NO list: a domain nobody has flagged, a clean IP, no path.
		Host: "cdn.brand-new-domain.example", JA3: badJA3,
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("a flow with a LISTED client fingerprint to an UNLISTED destination = %v, want BLOCK. "+
			"Domain, IP and URI intel all describe where a flow is going, and a family that rotates "+
			"domains defeats all three at once — the client stack is the axis that survives that",
			dec.GetAction())
	}
}

// A flow with an UNLISTED fingerprint to an unlisted destination is not blocked, so the test above is
// not passing because everything is blocked.
func TestAnUnlistedClientFingerprintDoesNotBlock(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "ja3 "+badJA3+"\n"))

	r := &gateway.Request{
		FlowID: "ja3-2", SrcIP: "10.0.0.5", DstIP: "93.184.216.34", Protocol: "tcp",
		Host: "www.example.com", JA3: "0123456789abcdef0123456789abcdef",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK {
		t.Fatal("an unlisted client fingerprint was blocked — the previous test would then pass " +
			"against an engine that blocks everything")
	}
}

// A JA3 MATCH IS REPORTED AS EVIDENCE, NOT AS PROOF.
//
// A domain or an IP identifies a specific endpoint somebody chose to list. A JA3 identifies a TLS LIBRARY
// AT A VERSION, shared by every program built on it — so a match is real evidence and is not, by itself,
// proof this flow is the malware. Reporting it at 1.0 alongside the destination indicators would put a
// legitimate application built on the same stack one policy rule away from being blocked, and the policy
// author would have no way to tell the two kinds of match apart.
//
// Mutation (report JA3 at 1.0 like the destination indicators): the confidences become equal → FAIL.
func TestAJA3MatchIsWeakerThanADestinationMatch(t *testing.T) {
	feed := feedTo(t, "domain c2.evil.com\nja3 "+badJA3+"\n")

	m, ok := feed.MatchJA3(badJA3)
	if !ok {
		t.Fatal("the listed fingerprint did not match")
	}
	if m.Category != nips.CategoryJA3 {
		t.Errorf("category = %v, want CategoryJA3 — a policy author must be able to tell a client "+
			"fingerprint match from a destination match", m.Category)
	}
	dest := feed.Match("c2.evil.com", "", "")
	if len(dest) == 0 {
		t.Fatal("the listed domain did not match")
	}
	if m.Confidence >= dest[0].Confidence {
		t.Fatalf("a JA3 match reports confidence %.2f, the same or more than a domain match's %.2f. A "+
			"JA3 identifies a TLS library shared by every program built on it: a match is evidence, "+
			"not proof, and equal confidence puts a legitimate application on the same stack one "+
			"policy rule away from being blocked", m.Confidence, dest[0].Confidence)
	}
}

// A MALFORMED JA3 INDICATOR IS REFUSED AT LOAD.
//
// Stored instead, it would sit in the feed looking like coverage and never fire once — a detection gap
// that reports itself as a detection, in the exact indicator somebody typed carefully enough to get
// slightly wrong.
//
// Mutation (accept any string as a ja3 indicator): the bad feeds load → FAIL.
func TestAMalformedJA3IndicatorIsRefusedAtLoad(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"too short", "ja3 abc123\n"},
		{"not hex", "ja3 zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n"},
		{"too long", "ja3 " + badJA3 + "00\n"},
		{"empty", "ja3\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := nips.ParseFeed(strings.NewReader(tc.line)); err == nil {
				t.Fatalf("accepted %q — it would sit in the feed looking like coverage and never "+
					"match once", strings.TrimSpace(tc.line))
			}
		})
	}
	// Case is normalised rather than refused: an operator pasting an upper-case digest from a report is
	// not making a mistake, and refusing it would be pedantry that costs coverage.
	f, err := nips.ParseFeed(strings.NewReader("ja3 " + strings.ToUpper(badJA3) + "\n"))
	if err != nil {
		t.Fatalf("an upper-case fingerprint was refused: %v", err)
	}
	if _, ok := f.MatchJA3(badJA3); !ok {
		t.Fatal("an upper-case indicator did not match its lower-case fingerprint — analysts paste " +
			"digests from reports in whatever case the report used")
	}
}
