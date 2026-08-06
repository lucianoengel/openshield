package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// CONSOLE-8: the fleet roster and the break-glass register.
//
// "'How do I stop this?' is the question a CISO asks before 'what does it detect?'" (INVARIANTS.md:131).
// The product could be stopped fleet-wide and recorded NOTHING about having been: issued_at, expires_at
// and reason were marshalled onto the wire and discarded, so "enforcement is off — since when, until
// when, why?" had no answer anywhere. `agent_enforcement` answers only what agents SAY, and its schema
// deliberately merges a fleet-issued disable with a local break-glass file, so it cannot be that answer.

const (
	disable = corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE
	restore = corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE
)

// execSQL runs a statement against the shared fixture database.
func execSQL(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// clearFleetControls drops rows another test in this package left behind. The register is keyed by a
// GLOBAL monotonic sequence, so a leftover control at a higher sequence than this test's would silently
// become the standing one and every derivation assertion below would be about the wrong row.
func clearFleetControls(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	execSQL(t, pool, `DELETE FROM fleet_controls`)
}

func seedControl(t *testing.T, s *controlplane.Server, verb corev1.FleetVerb, seq uint64,
	issued, expires time.Time) string {
	t.Helper()
	id := controlplane.FleetControlID(verb, seq)
	s.RecordFleetControlForTest(t, id, verb, seq, issued, expires, "seeded")
	return id
}

// TestAPublishedFleetControlIsRecordedAndARefusedOneIsNot.
//
// This is the ticket's core: the register must contain exactly the controls that reached the wire. The
// write sits BETWEEN the four-eyes gate and the publish, and both neighbours are asserted here.
//
// Mutation: move the record ABOVE the approval gate → the refused disable is recorded → FAILS.
// Mutation: drop the record call entirely → the approved disable is absent → FAILS.
func TestAPublishedFleetControlIsRecordedAndARefusedOneIsNot(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	url := embeddedNATS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetIntentSigner(priv)

	// A REFUSED disable must leave no trace. A register listing disables that were blocked is worse than
	// no register: it reports suppression that never happened.
	if _, err := srv.PublishFleetControl(ctx, disable, "unapproved", time.Hour); !errors.Is(
		err, controlplane.ErrFleetNotApproved) {
		t.Fatalf("err = %v, want ErrFleetNotApproved", err)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM fleet_controls`); n != 0 {
		t.Fatalf("%d control(s) recorded for a REFUSED disable — the register would name a suppression "+
			"that was blocked", n)
	}

	// Now approve one and publish it for real.
	seq, err := srv.NextFleetSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := controlplane.FleetControlID(disable, seq+1)
	aid, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectFleetControl, id,
		"cert:alice", "incident 41", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, aid, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.PublishFleetControl(ctx, disable, "incident 41", 90*time.Minute); err != nil {
		t.Fatalf("an approved disable was refused: %v", err)
	}

	got, err := srv.FleetControls(ctx, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("register holds %d controls, want exactly the one that was published", len(got))
	}
	c := got[0]
	if c.ControlID != id {
		t.Errorf("recorded %q, want the published id %q", c.ControlID, id)
	}
	if c.Reason != "incident 41" {
		t.Errorf("reason = %q — the operator's justification travelled on the wire and was the thing an "+
			"investigator most wants back", c.Reason)
	}
	// THE EXPIRY IS THE ONE THE FLEET RECEIVED, not one recomputed at read time. A register that
	// recomputes it can disagree with the endpoints about when protection returns.
	if d := c.ExpiresAt.Sub(c.IssuedAt); d < 89*time.Minute || d > 91*time.Minute {
		t.Errorf("recorded TTL = %v, want the 90m the control was published with", d)
	}
	if !c.Standing {
		t.Error("the only unexpired control is not reported as standing")
	}

	// AND THE FOUR-EYES PAIR IS READABLE. "By whom" for an action requiring two people is those two
	// people — and they are joined from `approvals` rather than copied, because the publishing path is an
	// operator-local command with no authenticated principal to record (see design.md / migration 046).
	if c.Requester == nil || *c.Requester != "cert:alice" {
		t.Errorf("requester = %v, want cert:alice", c.Requester)
	}
	if c.Approver == nil || *c.Approver != "cert:bob" {
		t.Errorf("approver = %v, want cert:bob — without it the register cannot say who suppressed "+
			"enforcement", c.Approver)
	}
}

// TestALapsedTimeToLiveEndsSuppressionWithNoWriter.
//
// The proto is explicit that a consumer treats an expired control as absent. If the operator surface
// stored a boolean instead of deriving one, ending suppression would need a sweeper — and a sweeper that
// falls behind reports protection as present when it is off.
//
// Mutation: drop the `expires_at > $1` predicate from FleetSuppression → FAILS.
func TestALapsedTimeToLiveEndsSuppressionWithNoWriter(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	ctx := context.Background()
	now := time.Now()

	seedControl(t, srv, disable, 900, now.Add(-2*time.Hour), now.Add(-time.Hour)) // lapsed

	suppressed, err := srv.FleetSuppression(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if suppressed {
		t.Fatal("a disable whose TTL lapsed an hour ago still suppresses the fleet — the console would " +
			"report the product as off while every endpoint enforces")
	}
	// And the register still SHOWS it, not standing: the history of who turned the product off does not
	// disappear when the control lapses.
	got, err := srv.FleetControls(ctx, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the lapsed control vanished from the register (%d rows) — its history is the audit", len(got))
	}
	if got[0].Standing {
		t.Error("a lapsed control is reported as standing")
	}
}

// TestALaterRestoreSupersedesAStandingDisable — enforcement comes back, and the surface says so.
//
// Mutation: take the FIRST row by sequence regardless of verb, or ignore the verb in FleetSuppression
// → FAILS.
func TestALaterRestoreSupersedesAStandingDisable(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	ctx := context.Background()
	now := time.Now()

	seedControl(t, srv, disable, 910, now.Add(-time.Hour), now.Add(time.Hour))
	if suppressed, err := srv.FleetSuppression(ctx, now); err != nil || !suppressed {
		t.Fatalf("suppressed = %v (err %v) with a standing disable — the assertion below would be "+
			"vacuous", suppressed, err)
	}

	seedControl(t, srv, restore, 911, now.Add(-time.Minute), now.Add(time.Hour))
	suppressed, err := srv.FleetSuppression(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if suppressed {
		t.Error("a RESTORE at a higher sequence did not end suppression — an operator who turned " +
			"enforcement back on would still be told the product is off")
	}
}

// TestSequenceDecidesWhichControlStandsNotWallClockTime.
//
// Consumers order by SEQUENCE (intent/fleetcontrol.go refuses anything at or below the highest applied).
// If the operator surface ordered by issued_at instead, clock skew between the control plane and the
// endpoints would let the console and the fleet disagree about whether the product is on.
//
// Mutation: ORDER BY issued_at DESC in FleetSuppression → FAILS.
func TestSequenceDecidesWhichControlStandsNotWallClockTime(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	ctx := context.Background()
	now := time.Now()

	// The RESTORE is later by sequence — which is what every consumer acts on — and EARLIER by clock,
	// as a control plane whose clock stepped backwards would produce.
	seedControl(t, srv, disable, 920, now.Add(-time.Minute), now.Add(time.Hour))
	seedControl(t, srv, restore, 921, now.Add(-30*time.Minute), now.Add(time.Hour))

	suppressed, err := srv.FleetSuppression(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if suppressed {
		t.Error("the surface followed wall-clock time and reported suppression, while every endpoint " +
			"follows the sequence and is enforcing — the two must not be able to disagree")
	}
}

// TestARestoreReportsNoApproverRatherThanAnEmptyOne.
//
// Restoring enforcement is deliberately NOT four-eyes gated, so a restore has no approval. "Not
// applicable" and "approved by nobody" must not serialize alike — which is why the pair is a pointer.
func TestARestoreReportsNoApproverRatherThanAnEmptyOne(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	ctx := context.Background()
	now := time.Now()

	seedControl(t, srv, restore, 930, now, now.Add(time.Hour))
	got, err := srv.FleetControls(ctx, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("register holds %d controls, want 1", len(got))
	}
	if got[0].Approver != nil {
		t.Errorf("approver = %q for an ungated restore — an empty identity reads as an approval that "+
			"happened", *got[0].Approver)
	}
	body := marshalJSON(t, got[0])
	if strings.Contains(body, `"approver"`) {
		t.Errorf("an absent approver is present on the wire: %s", body)
	}
}

// TestAnEnrolledAgentWithNoTelemetryIsNeverSeenNotLongSilent.
//
// The roster is authoritative, so an enrolled agent that has sent nothing still appears — with its facts
// ABSENT rather than defaulted. Serializing the zero time would put "silent for 2025 years" in front of
// an operator, and a field that is always absurd is a field nobody reads.
//
// Mutation: scan last-seen into a time.Time instead of a *time.Time → FAILS.
// Mutation: INNER JOIN fleet_telemetry instead of the correlated subquery → the agent vanishes → FAILS.
func TestAnEnrolledAgentWithNoTelemetryIsNeverSeenNotLongSilent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	execSQL(t, pool, `DELETE FROM agent_enforcement`)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	execSQL(t, pool, `DELETE FROM agent_identities`)

	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('silent-one', '\x00')`)
	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('talker', '\x00')`)
	srv.InsertFleetTelemetryForTest(t, "talker", "ev-1", []byte("x"), true)
	// SEC-3: an UNVERIFIED row must not advance last-seen, or an unsigned publisher keeps a dead agent
	// looking alive.
	srv.InsertFleetTelemetryForTest(t, "silent-one", "ev-2", []byte("x"), false)

	roster, err := srv.Fleet(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]controlplane.FleetAgent{}
	for _, a := range roster.Agents {
		byID[a.AgentID] = a
	}
	if len(byID) != 2 {
		t.Fatalf("roster holds %d agents, want both enrolled ones: %+v", len(byID), roster.Agents)
	}

	silent := byID["silent-one"]
	if silent.LastSeen != nil {
		t.Errorf("last_seen = %v for an agent whose only telemetry is UNVERIFIED — an unsigned publisher "+
			"must not be able to refresh liveness", silent.LastSeen)
	}
	if silent.SilentFor != nil {
		t.Error("silent_for is set for an agent that was never seen — a duration from the zero time is a " +
			"number, not a fact")
	}
	// NEVER REPORTED IS NOT ENFORCING. The two are different facts and the second must not be inferred
	// from the first — the same rule the fleet summary already states about silence.
	if silent.EnforcementDisabled != nil {
		t.Errorf("enforcement_disabled = %v for an agent that never acknowledged one",
			*silent.EnforcementDisabled)
	}

	if talker := byID["talker"]; talker.LastSeen == nil || talker.SilentFor == nil {
		t.Errorf("an agent WITH verified telemetry has no last-seen (%+v) — the negative assertions "+
			"above would then hold for a query that returns nothing at all", talker)
	}
}

// TestTheRosterCarriesTheAgentsOwnEnforcementReport — the agent's ACTUAL state, whether it came from a
// fleet control or its own local break-glass file, which the control plane has no other way to learn.
func TestTheRosterCarriesTheAgentsOwnEnforcementReport(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	execSQL(t, pool, `DELETE FROM agent_enforcement`)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	execSQL(t, pool, `DELETE FROM agent_identities`)

	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('stopped', '\x00')`)
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "stopped", true, 7))

	roster, err := srv.Fleet(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Agents) != 1 {
		t.Fatalf("roster = %+v, want the one enrolled agent", roster.Agents)
	}
	a := roster.Agents[0]
	if a.EnforcementDisabled == nil || !*a.EnforcementDisabled {
		t.Fatalf("enforcement_disabled = %v for an agent that reported it had stopped — this is the "+
			"whole break-glass question", a.EnforcementDisabled)
	}
	if a.AppliedSequence == nil || *a.AppliedSequence != 7 {
		t.Errorf("applied_sequence = %v, want 7 — without it an operator cannot tell a host that has "+
			"caught up from one that has not", a.AppliedSequence)
	}
}

// TestTheFleetRoutesAreServedToAnAnalystAndRefusedWithoutACredential.
//
// Mutation: drop either mux.HandleFunc → 404 and this FAILS. Mutation: remove the mount from
// enroll_http.go → the route-closure guard fails instead, which is the other half.
func TestTheFleetRoutesAreServedToAnAnalystAndRefusedWithoutACredential(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)

	for _, route := range []string{"/fleet", "/fleet/controls"} {
		rec := httptest.NewRecorder()
		controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
			ServeHTTP(rec, certReq(t, ca, http.MethodGet, route, "fleet-reader", "analyst"))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s as analyst = %d %q", route, rec.Code, strings.TrimSpace(rec.Body.String()))
		}

		anon := httptest.NewRecorder()
		controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
			ServeHTTP(anon, httptest.NewRequest(http.MethodGet, route, nil))
		if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusForbidden {
			t.Errorf("GET %s with NO credential = %d — the roster names every endpoint in the fleet and "+
				"which of them are not enforcing", route, anon.Code)
		}
	}
}

// TestTheRegisterSerializesAsAnArrayEvenWhenEmpty — a console rendering `null` needs a nil check that is
// exactly the difference between "nobody has ever disabled the fleet" and "we could not tell".
func TestTheRegisterSerializesAsAnArrayEvenWhenEmpty(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	clearFleetControls(t, pool)
	ca := newOneCA(t)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/fleet/controls", "fleet-reader", "analyst"))
	if body := rec.Body.String(); strings.Contains(body, `"controls":null`) {
		t.Errorf("an empty register serialized as null: %s", body)
	}
}

// TestAMalformedLimitIsRefusedRatherThanIgnored (SEC-8): silently falling back to the default hides that
// the caller asked for something else.
func TestAMalformedLimitIsRefusedRatherThanIgnored(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/fleet/controls?limit=nonsense", "fleet-reader", "analyst"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("GET /fleet/controls?limit=nonsense = %d, want 400", rec.Code)
	}
}

func marshalJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
