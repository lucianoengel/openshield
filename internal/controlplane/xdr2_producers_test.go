package controlplane_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// kindEventFor builds an Event of a specific KIND for a subject — the domain source the projection
// reads back off the persisted event (a Decision carries neither subject nor kind).
func kindEventFor(id, subject string, kind corev1.EventKind) *corev1.Event {
	return &corev1.Event{
		EventId: id,
		Subject: &corev1.Subject{PseudonymousId: subject},
		Kind:    kind,
	}
}

// seededSecret is content a real policy reason routinely quotes. It rides every seeded decision so the
// stored alert row can be asserted against it — the D10/D29 boundary proven on the persisted artifact,
// not only on the pure title function.
const seededSecret = "/home/alice/salaries-2026.xlsx"

func decisionFor(decisionID, eventID string, action corev1.Action, confidence float64) *corev1.Decision {
	return &corev1.Decision{
		DecisionId: decisionID,
		EventId:    eventID,
		Action:     action,
		Confidence: confidence,
		Reason:     "blocked: " + seededSecret + " matched CPF 123.456.789-09",
		DecidedAt:  timestamppb.New(time.Now().UTC()),
	}
}

// entityForAlias returns the entity id an alias resolves to, waiting for ingest to create it.
func entityForAlias(t *testing.T, kind, value string) int64 {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	var id int64
	waitFor(t, func() bool {
		err := pool.QueryRow(context.Background(),
			`SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`, kind, value).Scan(&id)
		return err == nil && id != 0
	})
	return id
}

func alertsByDomain(t *testing.T, srv *controlplane.Server, entityID int64) map[string]controlplane.UnifiedAlert {
	t.Helper()
	alerts, err := srv.AlertsForEntity(context.Background(), entityID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]controlplane.UnifiedAlert{}
	for _, a := range alerts {
		out[a.Domain] = a
	}
	return out
}

// TestDecisionsFromEveryDomainReachTheUnifiedStream is the XDR-2 increment-2 acceptance test, driven
// through the REAL verified-ingest path (signed envelopes, embedded NATS, real Postgres): a HIPS
// KILL_PROCESS and a network BLOCK on one host land as unified alerts sharing ONE entity key, and an
// ALLOW lands as nothing.
//
// Mutation A: key the alert by the producing agent_id instead of the event's subject → the two domains
// resolve to different entities → the shared-entity assertion FAILS.
// Mutation B: drop the ALLOW filter in alertableAction → a third row appears → the ALLOW assertion FAILS.
func TestDecisionsFromEveryDomainReachTheUnifiedStream(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr2-producers")
	ctx := context.Background()

	// ONE host: every event carries the same pseudonymous subject, which is what makes the
	// cross-domain grouping an entity join rather than a string match.
	subject := pseudonym.Of("agent-xdr2-producers")

	// Domain 1 — HIPS: a process exec the endpoint killed. Deliberately LOW confidence, to prove the
	// enforcement floor (a low-confidence kill is still a kill).
	if err := pub.PublishEvent(ctx, kindEventFor("evt-hips-1", subject, corev1.EventKind_EVENT_KIND_PROCESS_EXEC)); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishDecision(ctx, decisionFor("dec-hips-1", "evt-hips-1", corev1.Action_ACTION_KILL_PROCESS, 0.20)); err != nil {
		t.Fatal(err)
	}

	// Domain 2 — network: a DNS query the gateway blocked.
	if err := pub.PublishEvent(ctx, kindEventFor("evt-dns-1", subject, corev1.EventKind_EVENT_KIND_DNS_QUERY)); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishDecision(ctx, decisionFor("dec-dns-1", "evt-dns-1", corev1.Action_ACTION_BLOCK, 0.80)); err != nil {
		t.Fatal(err)
	}

	// And a decision that ALLOWED: the pipeline working, not a detection.
	if err := pub.PublishEvent(ctx, kindEventFor("evt-allow-1", subject, corev1.EventKind_EVENT_KIND_FILE_OPENED)); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishDecision(ctx, decisionFor("dec-allow-1", "evt-allow-1", corev1.Action_ACTION_ALLOW, 0.99)); err != nil {
		t.Fatal(err)
	}

	entityID := entityForAlias(t, xdr.KindDevice, subject)

	var byDomain map[string]controlplane.UnifiedAlert
	waitFor(t, func() bool {
		byDomain = alertsByDomain(t, srv, entityID)
		return len(byDomain) >= 2
	})

	hips, ok := byDomain["hips"]
	if !ok {
		t.Fatalf("no hips alert for entity %d; domains present: %v", entityID, byDomain)
	}
	nips, ok := byDomain["nips"]
	if !ok {
		t.Fatalf("no nips alert for entity %d; domains present: %v", entityID, byDomain)
	}
	// The shared entity key IS the deliverable — two domains, one asset (mutation A target).
	if hips.EntityID != nips.EntityID {
		t.Fatalf("cross-domain alerts landed on different entities: hips=%d nips=%d", hips.EntityID, nips.EntityID)
	}
	if hips.Severity != controlplane.SeverityHigh {
		t.Errorf("KILL_PROCESS at 0.20 confidence got severity %q, want %q (enforcement floor)",
			hips.Severity, controlplane.SeverityHigh)
	}
	if nips.Severity != controlplane.SeverityHigh {
		t.Errorf("BLOCK at 0.80 confidence got severity %q, want %q", nips.Severity, controlplane.SeverityHigh)
	}
	if hips.DedupKey != "decision:dec-hips-1" {
		t.Errorf("hips dedup key = %q, want the decision-namespaced key", hips.DedupKey)
	}
	// The D10/D29 boundary, asserted on the STORED row: every seeded decision carried a
	// content-quoting reason, and none of it may reach this widely-read derived table.
	// Mutation: build the title from Decision.reason → the secret appears here → this FAILS.
	for _, a := range []controlplane.UnifiedAlert{hips, nips} {
		if strings.Contains(a.Title, seededSecret) || strings.Contains(a.Title, "123.456.789-09") {
			t.Errorf("stored %s alert title leaked decision content: %q", a.Domain, a.Title)
		}
	}
	if hips.Title != "kill_process on process_exec" {
		t.Errorf("hips title = %q, want the enum-derived label", hips.Title)
	}

	// Mutation B target: an ALLOW is never an alert. The dlp domain must be absent entirely, since the
	// only dlp-kinded event in this test was the allowed one.
	if a, present := byDomain["dlp"]; present {
		t.Fatalf("an ALLOW decision produced a unified alert: %+v", a)
	}

	// The projection is not silently dropping work.
	if got := srv.UnprojectedDecisions.Load(); got != 0 {
		t.Errorf("UnprojectedDecisions = %d, want 0 — every alertable decision had its event", got)
	}
	if got := srv.UnifiedAlertFailures.Load(); got != 0 {
		t.Errorf("UnifiedAlertFailures = %d, want 0", got)
	}
}

// TestUserSubjectAlertJoinsLinkedDeviceEntity is the ZT shape: the access proxy authorizes on a USER
// identity and links device⋈user, so a denial's alert must land on the LINKED entity — beside the same
// host's endpoint alerts — not on an entity of its own.
//
// Mutation: remove the LookupAny call in entityForSubject → the user subject is minted as a NEW device
// alias on a NEW entity → the linked-entity assertion FAILS.
func TestUserSubjectAlertJoinsLinkedDeviceEntity(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const agentID = "agent-xdr2-zt"
	pub := signedAgent(t, srv, conn, agentID)
	ctx := context.Background()

	device := pseudonym.Of(agentID)
	const user = "zt-user@example.test"

	// The access proxy has already linked this user to this device (XDR-1-WIRE).
	pool := mustPoolCP(t)
	defer pool.Close()
	graph := xdr.NewStore(pool)
	linked, err := graph.Link(ctx, xdr.KindDevice, device, xdr.KindUser, user)
	if err != nil {
		t.Fatal(err)
	}

	// An endpoint detection on the DEVICE subject...
	if err := pub.PublishEvent(ctx, kindEventFor("evt-zt-hips", device, corev1.EventKind_EVENT_KIND_PROCESS_EXEC)); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishDecision(ctx, decisionFor("dec-zt-hips", "evt-zt-hips", corev1.Action_ACTION_KILL_PROCESS, 0.9)); err != nil {
		t.Fatal(err)
	}
	// ...and a gateway access denial on the USER subject, the ZT shape.
	if err := pub.PublishEvent(ctx, kindEventFor("evt-zt-access", user, corev1.EventKind_EVENT_KIND_HTTP_REQUEST)); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishDecision(ctx, decisionFor("dec-zt-access", "evt-zt-access", corev1.Action_ACTION_BLOCK, 0.7)); err != nil {
		t.Fatal(err)
	}

	var byDomain map[string]controlplane.UnifiedAlert
	waitFor(t, func() bool {
		byDomain = alertsByDomain(t, srv, linked)
		return len(byDomain) >= 2
	})
	hips, okH := byDomain["hips"]
	nips, okN := byDomain["nips"]
	if !okH || !okN {
		t.Fatalf("linked entity %d has domains %v, want both hips (device subject) and nips (user subject)",
			linked, byDomain)
	}
	if hips.EntityID != linked || nips.EntityID != linked {
		t.Fatalf("alerts landed on entities hips=%d nips=%d, want the linked %d", hips.EntityID, nips.EntityID, linked)
	}
	if nips.SubjectID != user {
		t.Errorf("the ZT alert's subject = %q, want the user identity %q", nips.SubjectID, user)
	}
}

// TestDecisionWithoutOriginatingEventIsCountedNotGuessed: a decision whose event never landed cannot be
// keyed to an entity. It is dropped and COUNTED — an agent-keyed or unkeyed row would group wrongly,
// which is worse than a missing one, and the counter is how a domain failing to reach correlation
// becomes visible instead of showing up as an empty incident list.
func TestDecisionWithoutOriginatingEventIsCountedNotGuessed(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr2-orphan")
	ctx := context.Background()

	before := srv.UnprojectedDecisions.Load()
	if err := pub.PublishDecision(ctx, decisionFor("dec-orphan", "evt-never-published", corev1.Action_ACTION_BLOCK, 0.9)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return srv.UnprojectedDecisions.Load() > before })

	pool := mustPoolCP(t)
	defer pool.Close()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM unified_alerts WHERE dedup_key=$1`, "decision:dec-orphan").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an unkeyable decision produced %d alert rows, want 0", n)
	}
}

// TestProjectionFailureDoesNotAffectIngest is the D38 derived-index property: with the entity graph
// pointed at a broken pool, the alert projection fails — and the decision is still persisted, the
// ingest still succeeds, and the failure is counted rather than surfaced.
func TestProjectionFailureDoesNotAffectIngest(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr2-brokengraph")
	ctx := context.Background()
	subject := pseudonym.Of("agent-xdr2-brokengraph")

	// The event must land BEFORE the graph is broken (the projection needs it persisted).
	if err := pub.PublishEvent(ctx, kindEventFor("evt-broken", subject, corev1.EventKind_EVENT_KIND_PROCESS_EXEC)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, err := srv.TelemetryForEvent(ctx, "evt-broken")
		return err == nil && len(rows) > 0
	})

	broken := mustPoolCP(t)
	broken.Close() // a closed pool: every graph call errors, exercising the best-effort path
	srv.SetEntityGraph(xdr.NewStore(broken))
	before := srv.UnifiedAlertFailures.Load()
	if err := pub.PublishDecision(ctx, decisionFor("dec-broken", "evt-broken", corev1.Action_ACTION_KILL_PROCESS, 0.9)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return srv.UnifiedAlertFailures.Load() > before })

	// The decision itself is durably persisted — the projection failing changed nothing about ingest.
	rows, err := srv.TelemetryForEvent(ctx, "evt-broken")
	if err != nil {
		t.Fatal(err)
	}
	var sawDecision bool
	for _, r := range rows {
		if r.Kind == "decision" {
			sawDecision = true
		}
	}
	if !sawDecision {
		t.Fatal("the decision was not persisted — a failing derived projection must not affect ingest")
	}
}
