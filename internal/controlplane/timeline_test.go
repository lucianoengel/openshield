package controlplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
	"google.golang.org/protobuf/proto"
)

// seededContent is the kind of string a real policy reason or file target carries. It rides the seeded
// ledger entry so the timeline's OUTPUT can be asserted against it (D10/D29 on this surface too).
const seededContent = "/home/alice/q4-salaries.xlsx"

// recordAlertWithEvidence seeds one unified alert carrying an evidence reference, through the real
// RecordUnifiedAlert path.
func recordAlertWithEvidence(t *testing.T, srv *controlplane.Server, domain, subject, severity, eventID, decisionID string, at time.Time) {
	t.Helper()
	if err := srv.RecordUnifiedAlert(context.Background(), controlplane.AlertRecord{
		Domain: domain, SubjectKind: xdr.KindDevice, Subject: subject, Severity: severity,
		Title: domain + " detection", DedupKey: domain + ":" + subject + ":" + at.Format(time.RFC3339Nano),
		DetectedAt: at, EventID: eventID, DecisionID: decisionID,
	}); err != nil {
		t.Fatalf("record %s alert: %v", domain, err)
	}
}

// seedLedgerEntry writes one audit_entries row for a decision — the EVIDENTIARY record the timeline
// resolves against (distinct from fleet_telemetry, which is the aggregate and not evidence, D30).
func seedLedgerEntry(t *testing.T, seq int64, decisionID, eventID string) []byte {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	hash := []byte{0xde, 0xad, 0xbe, 0xef, byte(seq)}
	// An entry may only reference an epoch whose public key is stored (migration 002's FK), so the
	// anchor epoch has to exist before a ledger row can.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO key_epochs (idx, public_key) VALUES (0, $1) ON CONFLICT (idx) DO NOTHING`,
		[]byte{0x02}); err != nil {
		t.Fatalf("seed key epoch: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO audit_entries (sequence, appended_at, prev_hash, hash, key_epoch, sig,
		                            decision_id, event_id, action, confidence, reason, subject_id, purpose,
		                            retention_class, outcome_kind, outcome_stage, policy_id, policy_version)
		 VALUES ($1, now(), $2, $3, 0, $4, $5, $6, $7, 0.9, $8, 'sub_x', $9, 0, '', '', 'p', 'v1')`,
		seq, []byte{0x00}, hash, []byte{0x01}, decisionID, eventID,
		int32(corev1.Action_ACTION_KILL_PROCESS), "blocked: "+seededContent+" matched",
		int32(corev1.Purpose_PURPOSE_DLP)); err != nil {
		t.Fatalf("seed ledger entry: %v", err)
	}
	return hash
}

// seedAggregateDecision writes a fleet_telemetry decision row — the AGGREGATE, which is explicitly not
// the evidentiary record (D30). It exists in this test only so that resolving evidence from the wrong
// table would visibly succeed, and be caught.
func seedAggregateDecision(t *testing.T, eventID, decisionID string) {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	payload, err := proto.Marshal(&corev1.Decision{DecisionId: decisionID, EventId: eventID,
		Action: corev1.Action_ACTION_KILL_PROCESS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified)
		 VALUES ('agent-xdr5','decision',$1,$2,true)`, eventID, payload); err != nil {
		t.Fatalf("seed aggregate decision: %v", err)
	}
}

// seedCrossDomainIncident records alerts for one entity and materializes the cross-domain incident,
// returning its id.
func seedCrossDomainIncident(t *testing.T, srv *controlplane.Server, now time.Time) int64 {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	var id int64
	if _, err := srv.MaterializeCrossDomainIncidents(context.Background(),
		controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM incidents WHERE kind='cross_domain' ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("find materialized incident: %v", err)
	}
	return id
}

// TestIncidentTimelineListsContributingAlertsInDetectionOrder is the XDR-5 acceptance test: the timeline
// of an XDR-4 incident lists ALL contributing alerts, cross-domain, in DETECTION order, each with the
// correct evidence state — one resolved to a real ledger entry, one unresolved, one a server derivation.
//
// Mutations: drop the incident_alerts write → the timeline is empty → FAILS. Order by alert id instead of
// detected_at → the detection order assertion FAILS. Resolve evidence from fleet_telemetry instead of
// audit_entries → the unresolved entry becomes resolved → FAILS.
func TestIncidentTimelineListsContributingAlertsInDetectionOrder(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := pseudonym.Of("agent-xdr5-timeline")

	// Insert in an order DIFFERENT from detection order, so ordering by id would be visibly wrong:
	// recorded newest-first, detected oldest-first.
	//   t-2m  nips  · has a ledger entry        → resolved
	//   t-5m  hips  · reference, no ledger row  → unresolved
	//   t-9m  ueba  · no reference at all       → derived
	recordAlertWithEvidence(t, srv, "nips", subject, controlplane.SeverityMedium,
		"evt-xdr5-nips", "dec-xdr5-nips", now.Add(-2*time.Minute))
	recordAlertWithEvidence(t, srv, "hips", subject, controlplane.SeverityHigh,
		"evt-xdr5-hips", "dec-xdr5-hips", now.Add(-5*time.Minute))
	recordAlert(t, srv, "ueba", subject, controlplane.SeverityLow, now.Add(-9*time.Minute))

	// Only the nips decision has an evidentiary LEDGER entry.
	wantHash := seedLedgerEntry(t, 1, "dec-xdr5-nips", "evt-xdr5-nips")
	// The hips decision, by contrast, exists in the fleet AGGREGATE and NOT in the ledger. That is what
	// makes the D30 mutation detectable: an implementation that resolves evidence from fleet_telemetry
	// would find this row and report the hips entry as "resolved", which is the confusion the aggregate's
	// whole docstring warns against — it is a queryable convenience, not the evidentiary record.
	seedAggregateDecision(t, "evt-xdr5-hips", "dec-xdr5-hips")

	incidentID := seedCrossDomainIncident(t, srv, now)
	entries, err := srv.IncidentTimeline(ctx, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("timeline has %d entries, want 3 (the contributing-alert join is not recorded): %+v",
			len(entries), entries)
	}

	// DETECTION order, not insertion order.
	gotOrder := []string{entries[0].Domain, entries[1].Domain, entries[2].Domain}
	if strings.Join(gotOrder, ",") != "ueba,hips,nips" {
		t.Errorf("timeline order = %v, want [ueba hips nips] (detection order, not alert-id order)", gotOrder)
	}

	byDomain := map[string]controlplane.TimelineEntry{}
	for _, e := range entries {
		byDomain[e.Domain] = e
	}

	// resolved: the ledger entry exists, and its coordinates are reported.
	nips := byDomain["nips"]
	if nips.Evidence != controlplane.EvidenceResolved {
		t.Errorf("nips entry evidence = %q, want %q", nips.Evidence, controlplane.EvidenceResolved)
	}
	if nips.LedgerSequence != 1 {
		t.Errorf("nips ledger sequence = %d, want 1", nips.LedgerSequence)
	}
	if nips.LedgerHash != hexOf(wantHash) {
		t.Errorf("nips ledger hash = %q, want %q", nips.LedgerHash, hexOf(wantHash))
	}

	// unresolved: a reference with no reachable ledger row — listed, reference intact, NOT resolved from
	// the aggregate (this is the D30 mutation's target).
	hips := byDomain["hips"]
	if hips.Evidence != controlplane.EvidenceUnresolved {
		t.Errorf("hips entry evidence = %q, want %q — a missing LEDGER row must not be resolved from the "+
			"fleet aggregate", hips.Evidence, controlplane.EvidenceUnresolved)
	}
	if hips.DecisionID != "dec-xdr5-hips" || hips.EventID != "evt-xdr5-hips" {
		t.Errorf("unresolved entry lost its reference: %+v", hips)
	}
	if hips.LedgerSequence != 0 || hips.LedgerHash != "" {
		t.Errorf("unresolved entry reports ledger coordinates it does not have: %+v", hips)
	}

	// derived: a server-side derivation with nothing to resolve.
	ueba := byDomain["ueba"]
	if ueba.Evidence != controlplane.EvidenceDerived {
		t.Errorf("ueba entry evidence = %q, want %q", ueba.Evidence, controlplane.EvidenceDerived)
	}
	if ueba.DecisionID != "" || ueba.EventID != "" {
		t.Errorf("a server derivation reported an evidence reference: %+v", ueba)
	}

	// D10/D29 on the timeline's own output: the seeded ledger reason quoted a path, and none of it may
	// surface here. The timeline LINKS to evidence; it never inlines content.
	for _, e := range entries {
		for _, field := range []string{e.Title, e.SubjectID, e.EventID, e.DecisionID, e.LedgerHash} {
			if strings.Contains(field, seededContent) {
				t.Errorf("timeline entry leaked content %q in %q", seededContent, field)
			}
		}
	}
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}

// TestTimelineContributionsAreIdempotent: re-materializing the same correlation must CONVERGE, not grow.
// A scheduled correlation loop (SOAR-2) re-runs the rule every tick and sees the same alerts each time.
//
// Mutation: drop ON CONFLICT DO NOTHING on the incident_alerts insert → the second run errors or
// duplicates → this FAILS.
func TestTimelineContributionsAreIdempotent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := pseudonym.Of("agent-xdr5-idempotent")

	recordAlertWithEvidence(t, srv, "hips", subject, controlplane.SeverityHigh, "e1", "d1", now.Add(-4*time.Minute))
	recordAlertWithEvidence(t, srv, "nips", subject, controlplane.SeverityHigh, "e2", "d2", now.Add(-2*time.Minute))

	rule := controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}
	for i := 0; i < 3; i++ {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, rule, now); err != nil {
			t.Fatalf("materialize %d: %v", i, err)
		}
	}
	var incidentID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM incidents WHERE kind='cross_domain' ORDER BY id DESC LIMIT 1`).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}
	var joins int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM incident_alerts WHERE incident_id=$1`, incidentID).Scan(&joins); err != nil {
		t.Fatal(err)
	}
	if joins != 2 {
		t.Fatalf("three materializations produced %d contribution rows, want 2 — the evidence set must "+
			"converge, not multiply per tick", joins)
	}
	// And the incident carries its domain list.
	var domains []string
	if err := pool.QueryRow(ctx, `SELECT domains FROM incidents WHERE id=$1`, incidentID).Scan(&domains); err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Errorf("incident domains = %v, want two", domains)
	}
}

// TestBurstIncidentHasNoTimeline: a single-domain burst incident correlates peer_alerts by subject and has
// no contributing-alert join, so it must REFUSE explicitly rather than return an empty list that would
// read as "nothing contributed to this incident".
func TestBurstIncidentHasNoTimeline(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst','sub_burst','open',3,0.9,1,now(),now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	_, err := srv.IncidentTimeline(ctx, id)
	if !errors.Is(err, controlplane.ErrNoTimelineForKind) {
		t.Fatalf("burst incident timeline error = %v, want ErrNoTimelineForKind (an empty list would read "+
			"as 'nothing contributed')", err)
	}
	// And an unknown id is not-found, not an empty timeline.
	if _, err := srv.IncidentTimeline(ctx, 999999); !errors.Is(err, controlplane.ErrIncidentNotFound) {
		t.Fatalf("unknown incident timeline error = %v, want ErrIncidentNotFound", err)
	}
}

// TestTimelineEndpointRecordsTheView: reading an incident timeline hands out evidence references, so it
// must leave a trace — the "who VIEWED an investigation, not only who acted" requirement (D20/L1).
//
// Mutation: remove the RecordView call in the handler → no investigation_views row → this FAILS.
func TestTimelineEndpointRecordsTheView(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")
	ctx := context.Background()
	now := time.Now().UTC()
	subject := pseudonym.Of("agent-xdr5-view")

	recordAlertWithEvidence(t, srv, "hips", subject, controlplane.SeverityHigh, "ev1", "dv1", now.Add(-4*time.Minute))
	recordAlertWithEvidence(t, srv, "nips", subject, controlplane.SeverityHigh, "ev2", "dv2", now.Add(-2*time.Minute))
	incidentID := seedCrossDomainIncident(t, srv, now)

	resp, err := op.Get("https://" + addr + "/incidents/timeline?id=" + itoa(incidentID))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET timeline = %d, want 200", resp.StatusCode)
	}
	var entries []controlplane.TimelineEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("endpoint returned %d entries, want 2", len(entries))
	}

	// The view is recorded, naming the verified operator.
	var views int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM investigation_views WHERE subject_filter=$1 AND viewer LIKE '%alice%'`,
		"incident:"+itoa(incidentID)).Scan(&views); err != nil {
		t.Fatal(err)
	}
	if views == 0 {
		t.Error("reading an incident timeline left no investigation_views row — evidence references were " +
			"handed out with no trace (D20/L1)")
	}

	// An unknown id is a 404, and a burst incident is an explicit refusal rather than an empty list.
	resp2, err := op.Get("https://" + addr + "/incidents/timeline?id=999999")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown incident timeline = %d, want 404", resp2.StatusCode)
	}

	var burstID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst','sub_burst_ep','open',3,0.9,1,now(),now()) RETURNING id`).Scan(&burstID); err != nil {
		t.Fatal(err)
	}
	resp3, err := op.Get("https://" + addr + "/incidents/timeline?id=" + itoa(burstID))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusConflict {
		t.Errorf("burst incident timeline = %d, want 409 with an explanation (never an empty list)", resp3.StatusCode)
	}

	// A non-operator is refused by the role gate.
	agent := clientWith(t, ca, "bob", "agent")
	resp4, err := agent.Get("https://" + addr + "/incidents/timeline?id=" + itoa(incidentID))
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusForbidden {
		t.Errorf("agent GET timeline = %d, want 403", resp4.StatusCode)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestProjectedAlertRecordsItsEvidenceReference / the peer-UEBA counterpart: the two producer shapes store
// what they should — a projected alert both ids, a server derivation neither (and nothing infers one).
func TestAlertEvidenceReferencesByProducerShape(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	projected := pseudonym.Of("agent-xdr5-projected")
	derived := pseudonym.Of("agent-xdr5-derived")
	recordAlertWithEvidence(t, srv, "hips", projected, controlplane.SeverityHigh, "evt-ref", "dec-ref", now)
	recordAlert(t, srv, "ueba", derived, controlplane.SeverityLow, now)

	var eventID, decisionID *string
	if err := pool.QueryRow(ctx,
		`SELECT event_id, decision_id FROM unified_alerts WHERE subject_id=$1`, projected).
		Scan(&eventID, &decisionID); err != nil {
		t.Fatal(err)
	}
	if eventID == nil || *eventID != "evt-ref" || decisionID == nil || *decisionID != "dec-ref" {
		t.Errorf("projected alert references = %v/%v, want evt-ref/dec-ref", eventID, decisionID)
	}

	if err := pool.QueryRow(ctx,
		`SELECT event_id, decision_id FROM unified_alerts WHERE subject_id=$1`, derived).
		Scan(&eventID, &decisionID); err != nil {
		t.Fatal(err)
	}
	if eventID != nil || decisionID != nil {
		t.Errorf("server-derived alert has references %v/%v, want both NULL — an empty string would look "+
			"like a reference that cannot resolve", eventID, decisionID)
	}
}
