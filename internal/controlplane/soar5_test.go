package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/nips"
)

// SOAR-5: signed threat-intel ingest, the shared IOC store, and incident enrichment.
//
// The two properties that carry the ticket:
//   - a feed that fails verification is refused AS A WHOLE and never parsed;
//   - enrichment reads observables the events already carry, matches them with the SAME matcher the
//     inline engine blocks with, and reads ONLY verified events.

const tiFeed = "domain evil.example\nip 203.0.113.9\ncidr 198.51.100.0/24\n"

func tiKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// seedNetworkEvent writes a fleet_telemetry event carrying network metadata — the observable enrichment
// reads. `verified` is a parameter because whether unverified telemetry may steer enrichment is itself a
// property under test (D44).
func seedNetworkEvent(t *testing.T, pool *pgxpool.Pool, eventID, subject, sniHost, dstIP string, verified bool) {
	t.Helper()
	ev := &corev1.Event{
		EventId:    eventID,
		AgentId:    "agent-soar5",
		Kind:       corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		ObservedAt: timestamppb.New(time.Now().UTC()),
		Subject:    &corev1.Subject{PseudonymousId: subject},
		Target:     &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: sniHost, DstIp: dstIP}},
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified) VALUES ($1,'event',$2,$3,$4)`,
		"agent-soar5", eventID, payload, verified); err != nil {
		t.Fatalf("seeding event %s: %v", eventID, err)
	}
}

// TestBadlySignedFeedStoresNothing — refusal is total, and it happens before the store is touched.
func TestBadlySignedFeedStoresNothing(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	pub, priv := tiKeypair(t)

	// A good ingest first, so the test proves the REFUSAL leaves the store alone rather than that an
	// empty store stayed empty.
	sig := ed25519.Sign(priv, []byte(tiFeed))
	if n, err := srv.IngestFeed(ctx, "vendor-a", []byte(tiFeed), sig, pub, nips.FormatNative); err != nil || n != 3 {
		t.Fatalf("good ingest: n=%d err=%v", n, err)
	}

	tampered := strings.Replace(tiFeed, "domain evil.example\n", "", 1)
	if _, err := srv.IngestFeed(ctx, "vendor-a", []byte(tampered), sig, pub, nips.FormatNative); err == nil {
		t.Fatal("a tampered feed was ingested — the signature is decorative")
	}
	if n := countRows(t, pool, `SELECT count(*) FROM ioc_indicators WHERE feed='vendor-a'`); n != 3 {
		t.Errorf("after a refused ingest the store holds %d indicators, want the previous 3 — a refusal "+
			"must not partially apply", n)
	}
	feed, err := srv.FeedFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Match("c2.evil.example", "", "")) != 1 {
		t.Error("the indicator the tampered feed tried to remove is gone — a partial apply happened")
	}
}

// TestIngestReplacesSoAWithdrawnIndicatorDisappears — a feed is a SNAPSHOT.
//
// Mutation: drop the DELETE (append instead of replace) → the withdrawn indicator survives → FAILS.
func TestIngestReplacesSoAWithdrawnIndicatorDisappears(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	pub, priv := tiKeypair(t)

	sign := func(body string) []byte { return ed25519.Sign(priv, []byte(body)) }

	first := "domain taken-down.example\ndomain still-bad.example\n"
	if _, err := srv.IngestFeed(ctx, "vendor-a", []byte(first), sign(first), pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}
	// A second, INDEPENDENT feed — its indicators must survive vendor-a's replacement.
	other := "domain other-feed.example\n"
	if _, err := srv.IngestFeed(ctx, "vendor-b", []byte(other), sign(other), pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}

	// The publisher withdraws one indicator (a takedown, or a retracted false positive).
	second := "domain still-bad.example\n"
	if _, err := srv.IngestFeed(ctx, "vendor-a", []byte(second), sign(second), pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}

	if n := countRows(t, pool,
		`SELECT count(*) FROM ioc_indicators WHERE feed='vendor-a' AND value='taken-down.example'`); n != 0 {
		t.Errorf("a withdrawn indicator survived re-ingest (%d rows) — an append-only store can never "+
			"retract a takedown or a false positive", n)
	}
	if n := countRows(t, pool,
		`SELECT count(*) FROM ioc_indicators WHERE feed='vendor-a' AND value='still-bad.example'`); n != 1 {
		t.Errorf("the retained indicator is gone (%d rows)", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM ioc_indicators WHERE feed='vendor-b'`); n != 1 {
		t.Errorf("re-ingesting one feed disturbed another (%d rows for vendor-b) — provenance is not "+
			"scoping the replacement", n)
	}

	// Provenance: which feed, which snapshot.
	feeds, err := srv.IngestedFeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var a *controlplane.FeedProvenance
	for i := range feeds {
		if feeds[i].Name == "vendor-a" {
			a = &feeds[i]
		}
	}
	if a == nil {
		t.Fatal("no provenance recorded for vendor-a")
	}
	if a.IndicatorCount != 1 || !a.Signed || a.Digest == "" {
		t.Errorf("provenance = %+v, want 1 indicator, signed, with a digest — an analyst cannot dispute "+
			"an indicator whose source and version are unknown", *a)
	}
}

// tiIncident seeds a two-domain incident whose alerts carry evidence references, through the REAL alert
// and correlation paths, and returns the incident id.
func tiIncident(t *testing.T, srv *controlplane.Server, pool *pgxpool.Pool, subject, sniHost, dstIP string, verified bool) int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	ev1, ev2 := "ev-"+subject+"-1", "ev-"+subject+"-2"
	seedNetworkEvent(t, pool, ev1, subject, sniHost, "", verified)
	seedNetworkEvent(t, pool, ev2, subject, "", dstIP, verified)
	recordAlertWithEvidence(t, srv, "nips", subject, controlplane.SeverityHigh, ev1, "", now.Add(-3*time.Minute))
	recordAlertWithEvidence(t, srv, "dlp", subject, controlplane.SeverityHigh, ev2, "", now.Add(-time.Minute))
	if _, err := srv.MaterializeCrossDomainIncidents(ctx,
		controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}, now); err != nil {
		t.Fatalf("materializing: %v", err)
	}
	var id int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM incidents WHERE kind='cross_domain' AND subject_id=$1`, subject).Scan(&id); err != nil {
		t.Fatalf("finding the incident for %s: %v", subject, err)
	}
	return id
}

// TestEnrichmentAnnotatesAKnownBadDestination is SOAR-5's acceptance case.
//
// The observable is one the event ALREADY carries (XDR-5's evidence reference → the verified event's
// NetworkSubject), so nothing new is collected. The match runs through the SHARED nips matcher.
//
// Mutation: remove the parent-suffix loop from nips.matchDomain (match the host exactly) → the subdomain
// misses → FAILS. That mutation also breaks the inline engine, which is the point: one matcher.
func TestEnrichmentAnnotatesAKnownBadDestination(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	pub, priv := tiKeypair(t)
	if _, err := srv.IngestFeed(ctx, "vendor-a", []byte(tiFeed), ed25519.Sign(priv, []byte(tiFeed)),
		pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}

	// A SUBDOMAIN of the feed's domain, plus an address inside the feed's CIDR.
	incID := tiIncident(t, srv, pool, "subject-soar5-hit", "c2.evil.example", "198.51.100.7", true)

	hits, err := srv.EnrichIncidentWithTI(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("enrichment found %d hits %+v, want 2 (the domain via parent-suffix, the IP via CIDR)",
			len(hits), hits)
	}
	byCat := map[string]controlplane.TIHit{}
	for _, h := range hits {
		byCat[h.Category] = h
	}
	dom, ok := byCat["ioc-domain"]
	if !ok || dom.Indicator != "evil.example" {
		t.Errorf("domain hit = %+v, want indicator evil.example", dom)
	}
	if len(dom.Feeds) != 1 || dom.Feeds[0] != "vendor-a" {
		t.Errorf("domain hit feeds = %v, want [vendor-a] — 'known bad' with no source is not something "+
			"an analyst can act on or dispute", dom.Feeds)
	}
	if ip, ok := byCat["ioc-ip"]; !ok || ip.Indicator != "198.51.100.0/24" {
		t.Errorf("ip hit = %+v, want the containing CIDR", ip)
	}

	// Through the PLAYBOOK, which is how this reaches an operator.
	pb := controlplane.Playbook{
		Name:    "ti-enrich",
		Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityLow},
		Steps:   []controlplane.Step{{Name: controlplane.StepEnrich}},
	}
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("playbook tick: %v", err)
	}
	annotations, err := srv.IncidentAnnotations(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	var ti *controlplane.IncidentAnnotation
	for i := range annotations {
		if annotations[i].Kind == "ti" {
			ti = &annotations[i]
		}
	}
	if ti == nil {
		t.Fatalf("the enrich step wrote no `ti` annotation (got %+v)", annotations)
	}
	if !strings.Contains(ti.Body, "evil.example") || !strings.Contains(ti.Body, "vendor-a") {
		t.Errorf("ti annotation %q names neither the indicator nor the feed", ti.Body)
	}
	// A hit is CONTEXT, not enforcement: nothing about the incident changed.
	var state, severityless string
	if err := pool.QueryRow(ctx, `SELECT state, coalesce(transitioned_by,'') FROM incidents WHERE id=$1`,
		incID).Scan(&state, &severityless); err != nil {
		t.Fatal(err)
	}
	if state != controlplane.IncidentOpen || severityless != "" {
		t.Errorf("a threat-intel hit advanced the incident (state=%q by=%q) — a public feed's assertion "+
			"must not become enforcement", state, severityless)
	}
}

// TestUnverifiedEvidenceDoesNotSteerEnrichment (D44).
//
// Unverified telemetry is not evidence. If it could steer enrichment, anyone able to publish unsigned
// telemetry could manufacture a "TI-confirmed" incident — or bury a real one — without holding a key.
//
// Mutation: drop `AND verified` from networkObservable → the unverified destination is annotated → FAILS.
func TestUnverifiedEvidenceDoesNotSteerEnrichment(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	pub, priv := tiKeypair(t)
	if _, err := srv.IngestFeed(ctx, "vendor-a", []byte(tiFeed), ed25519.Sign(priv, []byte(tiFeed)),
		pub, nips.FormatNative); err != nil {
		t.Fatal(err)
	}

	// The SAME known-bad destination, on UNVERIFIED events.
	unverified := tiIncident(t, srv, pool, "subject-soar5-unverified", "c2.evil.example", "198.51.100.7", false)
	hits, err := srv.EnrichIncidentWithTI(ctx, unverified)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("unverified telemetry produced %d threat-intel hit(s) %+v — unsigned telemetry must not "+
			"be able to manufacture confidence", len(hits), hits)
	}

	// And a VERIFIED incident with a clean destination gets nothing either, so the assertion above is
	// not passing merely because enrichment is inert.
	clean := tiIncident(t, srv, pool, "subject-soar5-clean", "cdn.good.example", "192.0.2.7", true)
	if hits, err := srv.EnrichIncidentWithTI(ctx, clean); err != nil || len(hits) != 0 {
		t.Errorf("a clean incident produced %+v (err %v), want no hits", hits, err)
	}
	pbClean := controlplane.Playbook{
		Name:    "ti-clean",
		Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityLow},
		Steps:   []controlplane.Step{{Name: controlplane.StepEnrich}},
	}
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pbClean}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE kind='ti'`); n != 0 {
		t.Errorf("%d `ti` annotation(s) written with no hit — an annotation that says 'nothing found' "+
			"trains an analyst to skip them", n)
	}
	// The verified, HIT incident above is a separate test; here the local-context annotation must still
	// have been written, proving enrich ran at all.
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE kind='enrichment'`); n == 0 {
		t.Error("the enrich step wrote no local-context annotation — it did not run, so the ti assertions "+
			"above are vacuous")
	}
}
