package controlplane_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest is SOAR-2's acceptance test, and it pins the
// gap this ticket closes: before it, BOTH materializers were called from exactly one place — the
// GET /incidents handler — so an incident existed only if a human happened to look, and SOAR-1's
// "pages automatically" was automatic only in the sense that the page followed someone else's request.
//
// Mutation: remove the materialize calls from the loop → no incident, no page → this FAILS.
func TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &countingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed a cross-domain burst through the REAL alert path. No HTTP request is made anywhere in this test.
	subject := pseudonym.Of("agent-soar2")
	recordAlert(t, srv, "hips", subject, controlplane.SeverityHigh, now.Add(-4*time.Minute))
	recordAlert(t, srv, "nips", subject, controlplane.SeverityHigh, now.Add(-2*time.Minute))

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// PLAT-5b: the interval and rules are read PER TICK from providers, so a configuration change reaches
	// a running loop without a restart.
	go srv.RunCorrelationLoop(loopCtx,
		func() time.Duration { return 50 * time.Millisecond },
		func() (controlplane.CorrelationRule, controlplane.CrossDomainRule) {
			return controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3},
				controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}
		},
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	// An incident appears without anyone asking for one.
	var incidents int
	waitFor(t, func() bool {
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE kind='cross_domain'`).Scan(&incidents)
		return incidents > 0
	})
	// And it paged.
	waitFor(t, func() bool { return sink.count() >= 1 })

	// Page-once still holds across many ticks (D220): the loop re-materializes constantly.
	time.Sleep(400 * time.Millisecond)
	if got := sink.count(); got != 1 {
		t.Errorf("the scheduled loop paged %d times for one incident, want 1 — a loop that re-pages every "+
			"tick is worse than no loop", got)
	}
	if controlplane.CorrelationFailures.Load() != 0 {
		t.Errorf("scheduled correlation reported %d failures", controlplane.CorrelationFailures.Load())
	}
}

// TestIncidentLifecycleIsForwardOnly: the lifecycle advances and is attributed, and a backward or unknown
// transition is refused.
//
// Mutation: drop the rank comparison from the UPDATE → the backward transition applies → this FAILS.
// Forward-only matters because MTTA/MTTR are derived from these timestamps: a state that can go backwards
// makes them unmeasurable.
func TestIncidentLifecycleIsForwardOnly(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst','sub_life','open',3,0.9,1,now(),now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// Forward, skipping a step, is allowed and attributed.
	if err := srv.TransitionIncident(ctx, id, controlplane.IncidentTriaged, "alice"); err != nil {
		t.Fatalf("open → triaged: %v", err)
	}
	var state, by string
	var at *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT state, coalesce(transitioned_by,''), transitioned_at FROM incidents WHERE id=$1`, id).
		Scan(&state, &by, &at); err != nil {
		t.Fatal(err)
	}
	if state != controlplane.IncidentTriaged || by != "alice" || at == nil {
		t.Fatalf("after transition: state=%q by=%q at=%v — the transition must be attributed", state, by, at)
	}

	// Backward is refused, and the state does not move.
	err := srv.TransitionIncident(ctx, id, controlplane.IncidentAcknowledged, "bob")
	if !errors.Is(err, controlplane.ErrBackwardTransition) {
		t.Fatalf("triaged → acknowledged err = %v, want ErrBackwardTransition", err)
	}
	if err := pool.QueryRow(ctx, `SELECT state FROM incidents WHERE id=$1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != controlplane.IncidentTriaged {
		t.Fatalf("a refused backward transition still changed the state to %q", state)
	}

	// Same state is also backward (not strictly forward).
	if err := srv.TransitionIncident(ctx, id, controlplane.IncidentTriaged, "bob"); !errors.Is(err, controlplane.ErrBackwardTransition) {
		t.Errorf("a same-state transition err = %v, want ErrBackwardTransition", err)
	}
	// An unknown state is refused rather than stored.
	if err := srv.TransitionIncident(ctx, id, "escalated-to-legal", "bob"); !errors.Is(err, controlplane.ErrUnknownState) {
		t.Errorf("unknown state err = %v, want ErrUnknownState", err)
	}
	// Forward to the end still works.
	if err := srv.TransitionIncident(ctx, id, controlplane.IncidentClosed, "carol"); err != nil {
		t.Errorf("triaged → closed: %v", err)
	}
	// An unknown incident is not-found.
	if err := srv.TransitionIncident(ctx, 999999, controlplane.IncidentClosed, "carol"); !errors.Is(err, controlplane.ErrIncidentNotFound) {
		t.Errorf("unknown incident err = %v, want ErrIncidentNotFound", err)
	}
}

// TestTransitionEndpointOutcomes: each refusal maps to the status an operator can act on.
func TestTransitionEndpointOutcomes(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")

	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst','sub_ep','open',3,0.9,1,now(),now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	post := func(path string) int {
		resp, err := op.Post("https://"+addr+path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("/incidents/transition?id=" + itoa(id) + "&to=contained"); got != http.StatusOK {
		t.Errorf("valid transition = %d, want 200", got)
	}
	if got := post("/incidents/transition?id=" + itoa(id) + "&to=open"); got != http.StatusConflict {
		t.Errorf("backward transition = %d, want 409 (well-formed but conflicting)", got)
	}
	if got := post("/incidents/transition?id=" + itoa(id) + "&to=nonsense"); got != http.StatusBadRequest {
		t.Errorf("unknown state = %d, want 400", got)
	}
	if got := post("/incidents/transition?id=999999&to=closed"); got != http.StatusNotFound {
		t.Errorf("unknown incident = %d, want 404", got)
	}
	agent := clientWith(t, ca, "bob", "agent")
	resp, err := agent.Post("https://"+addr+"/incidents/transition?id="+itoa(id)+"&to=closed", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("agent transition = %d, want 403", resp.StatusCode)
	}
}
