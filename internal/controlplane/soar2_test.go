package controlplane_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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

	// PLAT-5b: the interval and rules are read PER TICK from providers, so a configuration change reaches
	// a running loop without a restart. The helper is what STOPS the loop before the pool closes — see
	// its comment, and the assertion on CorrelationFailures at the end of this test.
	startCorrelationLoop(t, srv,
		func() time.Duration { return 50 * time.Millisecond },
		func() (controlplane.CorrelationRule, controlplane.CrossDomainRule) {
			return controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3},
				controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}
		},
		nil) // XDR-4c: no hunts configured — the breadth rule alone, the pre-hunt behaviour

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
	// CorrelationFailures is a PACKAGE-LEVEL counter, and this test deliberately does not reset it.
	// Resetting would make the assertion pass whether or not some other test in this binary left a
	// correlation loop running — which is precisely how this went red intermittently before
	// startCorrelationLoop existed, and a reset would have hidden the leak rather than fixed it. The
	// cost of not resetting is that the failure can be somebody else's, so the message says so.
	if n := controlplane.CorrelationFailures.Load(); n != 0 {
		t.Errorf("scheduled correlation reported %d failures — either this loop failed, or an EARLIER "+
			"test in this package leaked a RunCorrelationLoop goroutine that is still ticking against "+
			"a closed pool; start such loops with startCorrelationLoop, which joins them", n)
	}
}

// STOPPING THE LOOP IS NOT A CORRELATION FAILURE.
//
// The loop runs in the leader's context, so losing leadership (ADR-3) or shutting the process down
// cancels it — out from under whatever materialization is in flight, which then returns
// "context canceled". Counting that raised `openshield_correlation_failures_total`, whose published
// meaning is "incidents that should have been joined were not, and an attack spanning them reads as
// unrelated noise". Every demoted replica and every clean restart that landed mid-tick therefore
// reported broken detection, and an alarm that fires on an ordinary shutdown is one an operator learns
// to ignore.
//
// This was found while fixing a flaky test, and it is a PRODUCT defect rather than a test artifact:
// it fires in a running deployment on exactly the events a deployment performs most often.
//
// THE CANCELLATION IS FIRED FROM INSIDE THE PER-TICK RULES PROVIDER, which is the deterministic form of
// "the stop landed mid-tick": every query in that tick then runs on a context that is already done. The
// first tick is left alone and its incident is asserted, so the loop is proven to be doing real work
// before the tick that gets cancelled — a test where nothing ran would count nothing either, and pass
// while proving nothing. Waiting for the same collision to happen by luck was tried first and failed the
// mutation 4 times in 10: flaky in the direction of PASSING, which is the failure this change exists to
// remove.
//
// Mutation: drop the `stopping()` guard from the loop → the cancelled tick's errors are counted → this
// FAILS.
func TestStoppingTheCorrelationLoopIsNotAFailure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.SetNotifier(&countingSink{})
	ctx := context.Background()
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-loop-stop")
	recordAlert(t, srv, "hips", subject, controlplane.SeverityHigh, now.Add(-4*time.Minute))
	recordAlert(t, srv, "nips", subject, controlplane.SeverityHigh, now.Add(-2*time.Minute))

	// A DELTA, not a reset. The counter is package-level and another test's assertion depends on its
	// absolute value; zeroing it here would break that one's ability to see a leak. A delta asserts
	// what this test is about — that THIS stop counted nothing — without touching what anyone else sees.
	before := controlplane.CorrelationFailures.Load()

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var ticks int
	go func() {
		defer close(done)
		srv.RunCorrelationLoop(loopCtx,
			func() time.Duration { return time.Millisecond },
			func() (controlplane.CorrelationRule, controlplane.CrossDomainRule) {
				// Called once at the top of every tick. The SECOND tick is the one that gets stopped,
				// so the first has already materialized against a healthy pool.
				if ticks++; ticks == 2 {
					cancel()
				}
				return controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3},
					controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}
			},
			nil,
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the correlation loop did not return after its context was cancelled")
	}

	// The first tick did real work, so the second tick's queries were real queries that a cancelled
	// context aborted — not a loop that had nothing to do.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE kind='cross_domain'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no incident was materialized before the stop — this test would then be asserting that " +
			"a loop which did nothing counted nothing")
	}

	if got := controlplane.CorrelationFailures.Load(); got != before {
		t.Errorf("stopping the loop counted %d correlation failure(s) — a lost leadership or a clean "+
			"shutdown is not a detection failure, and a counter that rises on one is a false alarm on "+
			"the metric that exists to say detection stopped working", got-before)
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

// TestARealFailureDuringShutdownIsStillCounted.
//
// The first version of the stop guard tested the CONTEXT ALONE, and that is unsafe for a reason the
// reviewer traced: `leader.go` cancels the leader context when its Postgres ping fails, so a database
// outage produces a genuine pgx error AND a cancelled context in the same window. A context-only guard
// then discards the very failure `openshield_correlation_failures_total` exists to report — and, because
// the log call sat inside the same branch, discarded the log with it. No count, no line, nothing.
//
// Mutation: widen isLoopStop back to `ctx.Err() != nil` → the "real error while stopping" case FAILS.
// Mutation: narrow it to `errors.Is(err, context.Canceled)` alone → the "cancelled but live ctx" case
// FAILS, which is what keeps the exemption tied to THIS loop stopping rather than to any cancellation.
func TestARealFailureDuringShutdownIsStillCounted(t *testing.T) {
	live := context.Background()
	stopped, cancel := context.WithCancel(context.Background())
	cancel()

	dbDown := errors.New("conn closed")

	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"the loop's own cancellation, while stopping", stopped, context.Canceled, true},
		{"a REAL database failure that lands while stopping", stopped, dbDown, false},
		{"a real failure on a live loop", live, dbDown, false},
		// A cancellation arriving on a LIVE loop is somebody else's cancelled request, not this loop
		// shutting down — a real fault, and it must stay counted.
		{"a cancellation from elsewhere, loop still live", live, context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := controlplane.IsLoopStopForTest(tc.ctx, tc.err); got != tc.want {
				t.Errorf("isLoopStop = %v, want %v — %q", got, tc.want,
					"a guard that exempts this case either pages on every restart or hides a real outage")
			}
		})
	}
}
