package controlplane_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// countingSink counts delivered notifications, so "paged exactly once" is assertable.
type countingSink struct {
	mu  sync.Mutex
	got []notify.Notification
}

func (c *countingSink) Notify(_ context.Context, n notify.Notification) error {
	c.mu.Lock()
	c.got = append(c.got, n)
	c.mu.Unlock()
	return nil
}

func (c *countingSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// notifications returns a copy of what was delivered, so a test can assert on the TEXT an operator
// reads and not only on how many pages fired.
func (c *countingSink) notifications() []notify.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]notify.Notification(nil), c.got...)
}

// recordAlert seeds one unified alert through the REAL RecordUnifiedAlert path (entity resolution,
// dedup key, the lot) — never a direct INSERT, so the test exercises the same keying production does.
func recordAlert(t *testing.T, srv *controlplane.Server, domain, subject, severity string, at time.Time) {
	t.Helper()
	if err := srv.RecordUnifiedAlert(context.Background(), controlplane.AlertRecord{
		Domain: domain, SubjectKind: xdr.KindDevice, Subject: subject, Severity: severity,
		Title: domain + " detection", DedupKey: domain + ":" + subject + ":" + at.Format(time.RFC3339Nano),
		DetectedAt: at,
	}); err != nil {
		t.Fatalf("record %s alert for %s: %v", domain, subject, err)
	}
}

func entityOf(t *testing.T, srv *controlplane.Server, subject string) int64 {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`SELECT entity_id FROM entity_aliases WHERE value=$1 ORDER BY first_seen, kind LIMIT 1`,
		subject).Scan(&id); err != nil {
		t.Fatalf("entity for %s: %v", subject, err)
	}
	return id
}

// TestCrossDomainRuleRaisesOneIncidentPerEntity is the XDR-4 acceptance test. Three domains' alerts on
// ONE entity inside the window → exactly ONE cross-domain incident with domain_count=3, sourced from
// unified_alerts. The same three domains spread across DIFFERENT entities → nothing.
//
// Mutation B: remove the HAVING count(DISTINCT domain) >= n condition → the three single-domain entities
// each raise an incident → the negative half FAILS.
func TestCrossDomainRuleRaisesOneIncidentPerEntity(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// One asset, three domains, inside a 10-minute window.
	together := pseudonym.Of("agent-xdr4-together")
	recordAlert(t, srv, "hips", together, controlplane.SeverityHigh, now.Add(-5*time.Minute))
	recordAlert(t, srv, "nips", together, controlplane.SeverityMedium, now.Add(-3*time.Minute))
	recordAlert(t, srv, "ueba", together, controlplane.SeverityLow, now.Add(-1*time.Minute))

	// Three DIFFERENT assets, one domain each — the same three domains, no shared entity.
	apart := map[string]string{
		"hips": pseudonym.Of("agent-xdr4-apart-1"),
		"nips": pseudonym.Of("agent-xdr4-apart-2"),
		"ueba": pseudonym.Of("agent-xdr4-apart-3"),
	}
	for domain, subject := range apart {
		recordAlert(t, srv, domain, subject, controlplane.SeverityHigh, now.Add(-2*time.Minute))
	}

	rule := controlplane.CrossDomainRule{Window: 10 * time.Minute, MinDomains: 3}
	incidents, err := srv.CorrelateCrossDomain(ctx, rule, now)
	if err != nil {
		t.Fatal(err)
	}

	wantEntity := entityOf(t, srv, together)
	var matched []controlplane.CrossDomainIncident
	for _, inc := range incidents {
		if inc.EntityID == wantEntity {
			matched = append(matched, inc)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("got %d incidents for the multi-domain entity %d, want exactly 1 (all: %+v)",
			len(matched), wantEntity, incidents)
	}
	inc := matched[0]
	if inc.DomainCount != 3 {
		t.Errorf("domain_count = %d, want 3", inc.DomainCount)
	}
	if inc.AlertCount != 3 {
		t.Errorf("alert_count = %d, want 3", inc.AlertCount)
	}
	if len(inc.Domains) != 3 {
		t.Errorf("domains = %v, want three distinct", inc.Domains)
	}

	// The negative half (mutation B's target): a single-domain entity raises nothing.
	for domain, subject := range apart {
		e := entityOf(t, srv, subject)
		for _, got := range incidents {
			if got.EntityID == e {
				t.Errorf("single-domain entity %d (%s) raised a cross-domain incident: %+v", e, domain, got)
			}
		}
	}
}

// TestCrossDomainCorrelatesDeviceAndUserAsOneEntity is the entity-join property, which is the whole
// point of the rule: one asset named a device pseudonym by the endpoint and a user identity by the
// access proxy correlates as ONE thing.
//
// Mutation A: group by subject_id instead of entity_id → the asset splits into two single-domain groups
// → the incident never forms → this FAILS.
func TestCrossDomainCorrelatesDeviceAndUserAsOneEntity(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	device := pseudonym.Of("agent-xdr4-linked")
	const user = "xdr4-user@example.test"
	graph := xdr.NewStore(pool)
	linked, err := graph.Link(ctx, xdr.KindDevice, device, xdr.KindUser, user)
	if err != nil {
		t.Fatal(err)
	}

	// Two domains, two DIFFERENT subject strings, one linked entity.
	recordAlert(t, srv, "hips", device, controlplane.SeverityHigh, now.Add(-4*time.Minute))
	recordAlert(t, srv, "nips", user, controlplane.SeverityMedium, now.Add(-2*time.Minute))

	incidents, err := srv.CorrelateCrossDomain(ctx,
		controlplane.CrossDomainRule{Window: 10 * time.Minute, MinDomains: 2}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range incidents {
		if inc.EntityID == linked {
			if inc.DomainCount != 2 {
				t.Fatalf("linked entity incident domain_count = %d, want 2", inc.DomainCount)
			}
			return
		}
	}
	t.Fatalf("the device⋈user asset did not correlate: no incident for linked entity %d (got %+v)",
		linked, incidents)
}

// TestCrossDomainSequenceRuleRequiresOrder: the ordered-sequence rule on real data. The entity whose
// alerts arrived in the required order matches; the entity with the same domains in reverse does not.
//
// Mutation C: relax the check to set containment → the reversed entity matches → this FAILS.
func TestCrossDomainSequenceRuleRequiresOrder(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	forward := pseudonym.Of("agent-xdr4-seq-fwd")
	recordAlert(t, srv, "ueba", forward, controlplane.SeverityLow, now.Add(-9*time.Minute))
	recordAlert(t, srv, "hips", forward, controlplane.SeverityLow, now.Add(-6*time.Minute))
	recordAlert(t, srv, "nips", forward, controlplane.SeverityLow, now.Add(-3*time.Minute))

	reverse := pseudonym.Of("agent-xdr4-seq-rev")
	recordAlert(t, srv, "nips", reverse, controlplane.SeverityLow, now.Add(-9*time.Minute))
	recordAlert(t, srv, "hips", reverse, controlplane.SeverityLow, now.Add(-6*time.Minute))
	recordAlert(t, srv, "ueba", reverse, controlplane.SeverityLow, now.Add(-3*time.Minute))

	incidents, err := srv.CorrelateCrossDomain(ctx, controlplane.CrossDomainRule{
		Window:     10 * time.Minute,
		MinDomains: 3,
		Sequence:   []string{"ueba", "hips", "nips"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	fwdEntity, revEntity := entityOf(t, srv, forward), entityOf(t, srv, reverse)
	var sawForward bool
	for _, inc := range incidents {
		switch inc.EntityID {
		case fwdEntity:
			sawForward = true
			// Severity: three low alerts across three domains → two buckets above low.
			if inc.Severity != controlplane.SeverityHigh {
				t.Errorf("three low alerts across three domains gave severity %q, want %q",
					inc.Severity, controlplane.SeverityHigh)
			}
		case revEntity:
			t.Errorf("the REVERSED sequence matched: %+v — ordering is the rule's claim", inc)
		}
	}
	if !sawForward {
		t.Fatalf("the in-order entity %d did not match the sequence (got %+v)", fwdEntity, incidents)
	}
}

// TestMaterializeCrossDomainPagesOnce: a re-run extends the entity's open incident and does NOT re-page,
// the same property SOAR-1 established for the burst rule (D220).
//
// Mutation: drop the RETURNING (xmax = 0) insert-detection → the second materialization pages again →
// this FAILS.
func TestMaterializeCrossDomainPagesOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &countingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-xdr4-pageonce")
	recordAlert(t, srv, "hips", subject, controlplane.SeverityHigh, now.Add(-4*time.Minute))
	recordAlert(t, srv, "nips", subject, controlplane.SeverityHigh, now.Add(-2*time.Minute))

	rule := controlplane.CrossDomainRule{Window: 10 * time.Minute, MinDomains: 2}
	for i := 0; i < 2; i++ {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, rule, now); err != nil {
			t.Fatalf("materialize %d: %v", i, err)
		}
	}

	entityID := entityOf(t, srv, subject)
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE entity_id=$1 AND kind='cross_domain'`, entityID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("materializing twice produced %d incident rows, want 1", rows)
	}
	waitFor(t, func() bool { return sink.count() >= 1 })
	// Give any spurious second page time to arrive before asserting there wasn't one.
	time.Sleep(300 * time.Millisecond)
	if got := sink.count(); got != 1 {
		t.Fatalf("re-materialization paged %d times, want exactly 1", got)
	}
	// The delivery count ALONE does not prove the xmax insert-detection works: the SIEM-12 notify
	// dedupe would also suppress a second emit of the same id, so a broken detection would still
	// deliver once and this test would pass for the wrong reason. NotifyDeduped separates the layers —
	// it counts emits that were ATTEMPTED and then suppressed. A correct materializer never emits the
	// second time at all, so nothing reaches the dedupe.
	//
	// Mutation: replace RETURNING (xmax = 0) with a constant true → the second run emits → the dedupe
	// suppresses it → NotifyDeduped becomes 1 → this FAILS.
	if got := srv.NotifyDeduped.Load(); got != 0 {
		t.Fatalf("NotifyDeduped = %d, want 0 — the second materialization tried to page and was only "+
			"saved by the notify dedupe; the insert-vs-update detection is not doing its job", got)
	}
}

// TestBothIncidentKindsCoexist: the migration's kind-scoped uniqueness means a burst incident and a
// cross-domain incident for the SAME asset both survive. Before the reshape, the second upsert would
// have overwritten the first and an operator would have lost an incident with no trace.
func TestBothIncidentKindsCoexist(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	subject := pseudonym.Of("agent-xdr4-coexist")

	// Insert one of each kind for the same subject, the way the two materializers do.
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst',$1,'open',3,0.9,1,now(),now())`, subject); err != nil {
		t.Fatalf("insert burst incident: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (kind, subject_id, entity_id, state, alert_count, max_risk, host_count, domain_count, first_seen, last_seen)
		 VALUES ('cross_domain',$1,4242,'open',2,0,0,2,now(),now())`, subject); err != nil {
		t.Fatalf("insert cross-domain incident for the same subject: %v — the open-incident index is not kind-scoped", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE subject_id=$1 AND state='open'`, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("one asset has %d open incidents, want 2 (one per kind)", n)
	}

	// And each kind's uniqueness still HOLDS within itself.
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst',$1,'open',4,0.9,1,now(),now())`, subject); err == nil {
		t.Error("a second OPEN ueba_burst incident for one subject was accepted — uniqueness lost")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (kind, subject_id, entity_id, state, alert_count, max_risk, host_count, domain_count, first_seen, last_seen)
		 VALUES ('cross_domain','other',4242,'open',5,0,0,3,now(),now())`); err == nil {
		t.Error("a second OPEN cross_domain incident for one entity was accepted — uniqueness lost")
	}
}

// TestIncidentsRuleSelection (XDR-4): the cross-domain rule is selectable on the existing endpoint, the
// DEFAULT response is unchanged, and every malformed rule parameter is a 400 — never a silent
// fall-back, which would answer a different question than the operator asked while looking
// authoritative (SEC-8, the same discipline the burst params already follow).
func TestIncidentsRuleSelection(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")

	for _, path := range []string{
		"/incidents?rule=nonsense",                         // unknown rule name
		"/incidents?rule=cross_domain&min_domains=0",       // non-positive threshold
		"/incidents?rule=cross_domain&min_domains=abc",     // non-numeric threshold
		"/incidents?rule=cross_domain&window=notaduration", // malformed window
		"/incidents?rule=cross_domain&min_severity=urgent", // not a severity bucket
		"/incidents?rule=cross_domain&sequence=ueba,bogus", // a domain no producer emits
		// XDR-4b: a technique this build cannot derive would silently never match, and the operator
		// would read the empty list as "that attack chain did not happen".
		"/incidents?rule=cross_domain&technique_sequence=T1552,T9999", // not a technique at all
		"/incidents?rule=cross_domain&technique_sequence=T1552,T1486", // real ATT&CK, not derivable here
		"/incidents?rule=cross_domain&technique_sequence=T1567",       // the parent of a derived sub-technique
		"/incidents?rule=cross_domain&technique_sequence=t1552",       // case matters; the id is a key
	} {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (a malformed rule param was silently accepted)", path, resp.StatusCode)
		}
	}

	// The default (no rule param) and an explicit burst selection both still work...
	for _, path := range []string{"/incidents", "/incidents?rule=ueba_burst&min_alerts=3"} {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
	// ...and so does a well-formed cross-domain request with a sequence.
	resp, err := op.Get("https://" + addr +
		"/incidents?rule=cross_domain&min_domains=2&sequence=ueba,hips&technique_sequence=T1552,T1567.002")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid cross-domain /incidents = %d, want 200", resp.StatusCode)
	}
}
