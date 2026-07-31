package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/fieldmap"
)

// SIEM-13 at the search surface: ONE query reaches every source.
//
// The unit tests next door prove the map itself. This proves the thing an analyst actually does — a
// single hunt for a user, against real Postgres, over logs from three vendors that each named the field
// differently. Before this, that hunt took three queries and knowing three vocabularies, and forgetting
// one returned fewer rows rather than an error.
//
// Mutation (drop the fieldmap.Aliases expansion and search the literal key): the canonical key `user`
// matches nothing at all, since no source stores a field called "user" → FAIL on 0 results.
func TestOneCanonicalHuntReachesEveryVendor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(vendor, product string, fields map[string]string) {
		t.Helper()
		if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
			ReceivedAt: now, SourceHost: "h", Vendor: vendor, Product: product,
			SignatureID: "1", Name: "n", Severity: "5", Message: "m", Raw: "r", Fields: fields,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("arcsight", "firewall", map[string]string{"suser": "alice", "src": "10.1.1.5", "act": "blocked"})
	seed("aws", "cloudtrail", map[string]string{"userIdentityArn": "alice", "sourceIPAddress": "10.1.1.5", "eventName": "GetObject"})
	seed("microsoft", "windows", map[string]string{"SubjectUserName": "alice", "IpAddress": "10.1.1.5", "NewProcessName": `C:\cmd.exe`})
	// Somebody else, in each vocabulary — so a passing result cannot come from matching everything.
	seed("arcsight", "firewall", map[string]string{"suser": "mallory", "src": "10.4.4.4"})
	seed("aws", "cloudtrail", map[string]string{"userIdentityArn": "mallory", "sourceIPAddress": "10.4.4.4"})

	got, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{
		FieldKey: fieldmap.User, FieldValue: "alice", Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("one canonical hunt for user=alice returned %d log(s), want 3 (CEF, CloudTrail, "+
			"Windows) — a hunt that misses a source returns fewer rows and reads as a narrower blast "+
			"radius, so the gap looks like good news", len(got))
	}
	vendors := map[string]bool{}
	for _, g := range got {
		vendors[g.Vendor] = true
		if g.Normalized[fieldmap.User] != "alice" {
			t.Errorf("%s/%s: normalized user = %q, want \"alice\" — the analyst reading the result "+
				"still has to know this vendor's own field name", g.Vendor, g.Product,
				g.Normalized[fieldmap.User])
		}
		// The raw fields are untouched: normalisation is additive, never a replacement.
		if len(g.Fields) == 0 {
			t.Errorf("%s/%s: raw fields were lost — the stored truth must survive normalisation",
				g.Vendor, g.Product)
		}
	}
	if len(vendors) != 3 {
		t.Fatalf("results span %d vendor(s), want 3: %v", len(vendors), vendors)
	}
}

// A VENDOR-SPECIFIC KEY STILL MEANS EXACTLY WHAT IT MEANT.
//
// An analyst who knows a source's own field name has a precise search, and this must not silently start
// matching more. Widening an existing query is not a compatible change — it is the same wrong answer as
// missing a source, with the sign flipped.
//
// Mutation (expand every key through the map, or fall back to the canonical set when a key is unknown):
// `suser:alice` also matches the CloudTrail and Windows rows → FAIL on 1 vs 3.
func TestAVendorSpecificKeyIsNotWidened(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(vendor string, fields map[string]string) {
		t.Helper()
		if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
			ReceivedAt: now, Vendor: vendor, Product: "p", Fields: fields,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("arcsight", map[string]string{"suser": "alice"})
	seed("aws", map[string]string{"userIdentityArn": "alice"})
	seed("microsoft", map[string]string{"SubjectUserName": "alice"})

	got, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{
		FieldKey: "suser", FieldValue: "alice", Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("hunting the vendor's OWN key suser=alice returned %d log(s), want 1 — a precise "+
			"query that silently starts matching three sources is as wrong as one that misses two",
			len(got))
	}
	if got[0].Vendor != "arcsight" {
		t.Fatalf("matched %s, want the CEF log", got[0].Vendor)
	}
}
