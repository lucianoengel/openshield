package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// recordTechAlert seeds one unified alert carrying ATT&CK techniques, through the REAL
// RecordUnifiedAlert path — the same keying, dedup and array write production uses.
func recordTechAlert(t *testing.T, srv *controlplane.Server, domain, subject string,
	at time.Time, techniques ...string) {
	t.Helper()
	if err := srv.RecordUnifiedAlert(context.Background(), controlplane.AlertRecord{
		Domain: domain, SubjectKind: xdr.KindDevice, Subject: subject,
		Severity: controlplane.SeverityHigh, Title: domain + " detection",
		DedupKey:   "tech:" + domain + ":" + subject + ":" + at.Format(time.RFC3339Nano),
		DetectedAt: at, Techniques: techniques,
	}); err != nil {
		t.Fatalf("record %s alert for %s: %v", domain, subject, err)
	}
}

func techIncidentFor(t *testing.T, incidents []controlplane.CrossDomainIncident, entity int64) (controlplane.CrossDomainIncident, bool) {
	t.Helper()
	for _, inc := range incidents {
		if inc.EntityID == entity {
			return inc, true
		}
	}
	return controlplane.CrossDomainIncident{}, false
}

// TestATechniqueSequenceSelectsTheChainAndNotItsPermutations is the XDR-4b acceptance test, over a
// real database with the real ragged-array aggregation.
//
// Three assets, all satisfying the plain cross-domain rule (two domains each), distinguished ONLY by
// their techniques:
//   - chained:  T1552 on one alert, then T1567.002 on a later one — the hunt's chain.
//   - reversed: the same two techniques in the opposite order — a different claim, not a match.
//   - combined: BOTH techniques on a SINGLE alert — one moment cannot evidence "then".
//
// Mutation: let a step match the same alert as its predecessor (drop the `break` in
// matchesTechniqueSequence) → `combined` matches → the test FAILS.
func TestATechniqueSequenceSelectsTheChainAndNotItsPermutations(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	chained := pseudonym.Of("agent-xdr4b-chained")
	recordTechAlert(t, srv, "dlp", chained, now.Add(-6*time.Minute), "T1552")
	recordTechAlert(t, srv, "nips", chained, now.Add(-2*time.Minute), "T1567.002")

	reversed := pseudonym.Of("agent-xdr4b-reversed")
	recordTechAlert(t, srv, "dlp", reversed, now.Add(-6*time.Minute), "T1567.002")
	recordTechAlert(t, srv, "nips", reversed, now.Add(-2*time.Minute), "T1552")

	combined := pseudonym.Of("agent-xdr4b-combined")
	recordTechAlert(t, srv, "dlp", combined, now.Add(-6*time.Minute), "T1552", "T1567.002")
	recordTechAlert(t, srv, "nips", combined, now.Add(-2*time.Minute), "T1027")

	// An asset with no techniques at all: it must still correlate under the plain rule, and must not
	// be swept in by a technique hunt. NULL is not a wildcard.
	bare := pseudonym.Of("agent-xdr4b-bare")
	recordTechAlert(t, srv, "dlp", bare, now.Add(-6*time.Minute))
	recordTechAlert(t, srv, "nips", bare, now.Add(-2*time.Minute))

	entities := map[string]int64{
		"chained":  entityOf(t, srv, chained),
		"reversed": entityOf(t, srv, reversed),
		"combined": entityOf(t, srv, combined),
		"bare":     entityOf(t, srv, bare),
	}

	// Baseline: WITHOUT the technique constraint, all four correlate. Otherwise a later assertion
	// that only `chained` matched would prove nothing — the others might have been excluded by the
	// window, the domain count or the ragged aggregation erroring out.
	base := controlplane.CrossDomainRule{Window: 10 * time.Minute, MinDomains: 2}
	all, err := srv.CorrelateCrossDomain(ctx, base, now)
	if err != nil {
		t.Fatalf("baseline correlation: %v", err)
	}
	for name, id := range entities {
		if _, ok := techIncidentFor(t, all, id); !ok {
			t.Fatalf("%s does not correlate even without a technique constraint — the negative "+
				"halves below would pass vacuously", name)
		}
	}

	hunt := base
	hunt.TechniqueSequence = []string{"T1552", "T1567.002"}
	got, err := srv.CorrelateCrossDomain(ctx, hunt, now)
	if err != nil {
		t.Fatalf("technique correlation: %v", err)
	}

	inc, ok := techIncidentFor(t, got, entities["chained"])
	if !ok {
		t.Fatal("the chained asset did not match T1552 → T1567.002")
	}
	// The incident reports what it saw, in first-seen order.
	if len(inc.Techniques) != 2 || inc.Techniques[0] != "T1552" || inc.Techniques[1] != "T1567.002" {
		t.Errorf("Techniques = %v, want [T1552 T1567.002] in first-seen order", inc.Techniques)
	}

	for _, name := range []string{"reversed", "combined", "bare"} {
		if _, ok := techIncidentFor(t, got, entities[name]); ok {
			t.Errorf("%s matched T1552 → T1567.002, but it does not evidence that chain", name)
		}
	}
}

// A decision's techniques must survive the whole projection path — Decision → contract check →
// unified_alerts → correlation. Asserting the array round-trips through Postgres is the point: the
// aggregation that reads it back is the one shape that fails only on real, ragged data.
func TestTheTechniquesTheDecisionCarriedReachCorrelation(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-xdr4b-roundtrip")
	// Ragged on purpose: three techniques, then one, then none.
	recordTechAlert(t, srv, "hips", subject, now.Add(-9*time.Minute), "T1218", "T1027", "T1059")
	recordTechAlert(t, srv, "dlp", subject, now.Add(-5*time.Minute), "T1552")
	recordTechAlert(t, srv, "nips", subject, now.Add(-1*time.Minute))

	incidents, err := srv.CorrelateCrossDomain(ctx,
		controlplane.CrossDomainRule{Window: 15 * time.Minute, MinDomains: 2}, now)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	inc, ok := techIncidentFor(t, incidents, entityOf(t, srv, subject))
	if !ok {
		t.Fatal("no incident for the round-trip asset")
	}
	want := []string{"T1218", "T1027", "T1059", "T1552"}
	if len(inc.Techniques) != len(want) {
		t.Fatalf("Techniques = %v, want %v", inc.Techniques, want)
	}
	for i := range want {
		if inc.Techniques[i] != want[i] {
			t.Fatalf("Techniques = %v, want %v (first-seen order, within an alert as stored)",
				inc.Techniques, want)
		}
	}
	// And the ordering claim holds across the ragged rows: T1218 came before T1552.
	fwd := controlplane.CrossDomainRule{Window: 15 * time.Minute, MinDomains: 2,
		TechniqueSequence: []string{"T1218", "T1552"}}
	f, err := srv.CorrelateCrossDomain(ctx, fwd, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := techIncidentFor(t, f, entityOf(t, srv, subject)); !ok {
		t.Error("T1218 → T1552 did not match, though the alerts carry it in that order")
	}
	rev := fwd
	rev.TechniqueSequence = []string{"T1552", "T1218"}
	r, err := srv.CorrelateCrossDomain(ctx, rev, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := techIncidentFor(t, r, entityOf(t, srv, subject)); ok {
		t.Error("T1552 → T1218 matched, but that is the reverse of what happened")
	}
}

// The operator-facing path: GET /incidents?rule=cross_domain&technique_sequence=… returns the
// matching incident WITH its techniques in the JSON, and returns nothing for a chain the alerts do
// not evidence. Everything above proves the rule; this proves an operator can actually ask it.
func TestAnOperatorCanHuntByTechniqueOverHTTP(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-xdr4b-http")
	recordTechAlert(t, srv, "dlp", subject, now.Add(-4*time.Minute), "T1552")
	recordTechAlert(t, srv, "hips", subject, now.Add(-2*time.Minute), "T1218", "T1567.002")
	entity := entityOf(t, srv, subject)

	hunt := func(t *testing.T, seq string) []controlplane.CrossDomainIncident {
		t.Helper()
		resp, err := op.Get("https://" + addr +
			"/incidents?rule=cross_domain&min_domains=2&window=10m&technique_sequence=" + seq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET technique_sequence=%s = %d, want 200", seq, resp.StatusCode)
		}
		// CONSOLE-6b: one route, one envelope — this branch answers {rows, has_more} like the walkable
		// one, so a console has a single shape to decode from /incidents.
		var out controlplane.CrossDomainPage
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out.Rows
	}

	inc, ok := techIncidentFor(t, hunt(t, "T1552,T1567.002"), entity)
	if !ok {
		t.Fatal("the chain the alerts evidence returned no incident over HTTP")
	}
	// The techniques reach the operator, not just the rule — otherwise a matching incident would give
	// no way to see WHY it matched.
	seen := map[string]bool{}
	for _, id := range inc.Techniques {
		seen[id] = true
	}
	for _, want := range []string{"T1552", "T1218", "T1567.002"} {
		if !seen[want] {
			t.Errorf("incident techniques = %v, missing %s", inc.Techniques, want)
		}
	}

	// A chain these alerts do not evidence: T1567.002 came AFTER T1552, never before it.
	if _, ok := techIncidentFor(t, hunt(t, "T1567.002,T1552"), entity); ok {
		t.Error("the reversed chain matched over HTTP — the ordering claim did not survive the handler")
	}
}
