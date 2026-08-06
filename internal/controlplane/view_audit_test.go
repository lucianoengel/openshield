package controlplane_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-5. docs/threat-model.md bounds the malicious insider with an operator role with one sentence:
// "who LOOKED is recorded, not only who acted, and the record is written BEFORE the evidence is
// returned". It was true of four routes and false of the console's primary ones — `/alerts`, `/search`,
// `/events`, `/logs`, `/searches/run`, `/incidents`, `/incidents/recurrences` and `/entities` recorded
// nothing at all.
//
// These cases assert the wrapper that inverts the default: recorded unless a route is named in a table
// with the residual it accepts.

// viewsFor returns the recorded views for a viewer. It reads through the shipped reader (ViewsBy), so a
// test cannot pass against rows the production read path could not see.
func viewsFor(t *testing.T, s *controlplane.Server, viewer string) []controlplane.ViewRecord {
	t.Helper()
	recs, err := s.ViewsBy(context.Background(), viewer)
	if err != nil {
		t.Fatalf("reading views for %s: %v", viewer, err)
	}
	return recs
}

// TestAnAuditedReadIsRecordedBeforeItIsServed is the ORDERING claim, and it is the reason the inner
// handler queries the table instead of the test doing so afterwards.
//
// A test that asserted the row after the response would pass equally against a wrapper that recorded
// AFTER serving — which is the version an insider defeats by killing the connection mid-response. Here
// the handler itself fails the test if the record is not already there when it runs.
//
// Mutation: move the recordViewDetail call in viewAudited to after h.ServeHTTP → the inner handler sees
// no row and this FAILS.
func TestAnAuditedReadIsRecordedBeforeItIsServed(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	const cn = "audit-order"
	const principal = "cert:" + cn
	grantOperator(t, s, ca, cn, controlplane.RoleAnalyst)

	var sawRecordFirst bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The read handler's own moment: by now the accountability record must already exist.
		sawRecordFirst = len(viewsFor(t, s, principal)) == 1
		w.WriteHeader(http.StatusOK)
	})
	gate := controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst,
		controlplane.ViewAuditedForTest(s, inner))

	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/events?agent=host-7&kind=file", cn, "agent"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the audited read was not served: %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !sawRecordFirst {
		t.Fatal("the read handler ran before the view was recorded — a record written after the evidence " +
			"is a record an operator can avoid by not waiting for the response, which is the whole of " +
			"what 'recorded BEFORE the evidence is returned' means")
	}

	// ...and the record says WHAT was read, not only that a read happened. Before CONSOLE-5 the schema
	// could not carry this, so "an operator read the event search" did not distinguish a dashboard
	// refresh from a search for one named host.
	recs := viewsFor(t, s, principal)
	if len(recs) != 1 {
		t.Fatalf("recorded %d views, want exactly 1", len(recs))
	}
	if recs[0].Route != "/events" {
		t.Errorf("recorded route %q, want /events", recs[0].Route)
	}
	if !strings.Contains(recs[0].Query, "agent=host-7") {
		t.Errorf("recorded query %q does not carry the filter that selected the rows", recs[0].Query)
	}
}

// TestAReadThatCannotBeRecordedIsRefusedAndTheHandlerNeverRuns is the invariant that makes the record
// worth having. An operator who can make the recording fail and still receive the evidence has an
// unaudited read.
//
// BOTH HALVES ARE ASSERTED. A test that only checked the status would pass against a wrapper that served
// the evidence and then wrote an error status over an already-flushed body.
//
// The tier gate is deliberately NOT in the path — see ViewAuditedAsForTest for why leaving it in would
// make this vacuous.
//
// Mutation: in viewAudited, log the record error and fall through to h.ServeHTTP → this FAILS on the
// handler-ran check.
func TestAReadThatCannotBeRecordedIsRefusedAndTheHandlerNeverRuns(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)

	var handlerRan bool
	audited := controlplane.ViewAuditedAsForTest(s, "audit-dberr",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

	// FIRST, ALIVE. Without this the failure below is satisfied by a wrapper that refuses every read,
	// and by a fixture that was broken before the pool was closed.
	rec := httptest.NewRecorder()
	audited.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	if rec.Code != http.StatusOK || !handlerRan {
		t.Fatalf("the audited read was not served against a live database: %d, handler ran=%v",
			rec.Code, handlerRan)
	}

	handlerRan = false
	pool.Close() // simulate a database that cannot accept the record

	rec = httptest.NewRecorder()
	audited.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	if handlerRan {
		t.Fatal("the read handler ran even though the view could not be recorded — an operator who can " +
			"break the recording and still receive the evidence has an unaudited read")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("an unrecordable read answered %d, want 500", rec.Code)
	}
}

// TestAnExemptRouteRecordsNothingAndAnAuditedOneDoes asserts BOTH halves, because the negative alone is
// vacuous: "no row was written for /health" passes perfectly against a wrapper that records nothing at
// all, which is precisely the state CONSOLE-5 exists to leave.
//
// Mutation: remove "/health" from viewAuditExempt → the exempt half FAILS. Make viewAudited return h
// unchanged → the audited half FAILS.
func TestAnExemptRouteRecordsNothingAndAnAuditedOneDoes(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	const cn = "audit-exempt"
	const principal = "cert:" + cn
	grantOperator(t, s, ca, cn, controlplane.RoleAnalyst)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gate := controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst,
		controlplane.ViewAuditedForTest(s, inner))

	serve := func(method, path string) {
		t.Helper()
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, certReq(t, ca, method, path, cn, "agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %q", method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}

	// The platform's own liveness report names no subject, so it is exempt WITH THE REASON WRITTEN DOWN.
	serve(http.MethodGet, "/health")
	if got := viewsFor(t, s, principal); len(got) != 0 {
		t.Errorf("an exempt route recorded %d views", len(got))
	}
	// A write is attributed by the act record it produces, not by a view row that would duplicate it.
	serve(http.MethodPost, "/alerts/ack?id=1")
	if got := viewsFor(t, s, principal); len(got) != 0 {
		t.Errorf("a write recorded %d views — a view row for an act makes investigation_views a partial "+
			"duplicate of the act log", len(got))
	}
	// THE POSITIVE HALF. Without it every assertion above is satisfied by a feature that does nothing.
	serve(http.MethodGet, "/alerts?limit=5")
	got := viewsFor(t, s, principal)
	if len(got) != 1 || got[0].Route != "/alerts" {
		t.Fatalf("the analyst detection queue recorded %d views (%+v), want exactly one naming /alerts",
			len(got), got)
	}
}

// TestAReadReachingTheViewAuditWithNoPrincipalIsRefused. Past the tier gate this is impossible, so it
// means the wrapper was mounted OUTSIDE requireGrant — a wiring bug, not an authorization outcome.
// Serving the read anyway would be an unaudited read caused by a mistake in a file nobody edits.
//
// Mutation: make viewAudited fall through to h.ServeHTTP when the viewer is empty → this FAILS.
func TestAReadReachingTheViewAuditWithNoPrincipalIsRefused(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)

	var handlerRan bool
	audited := controlplane.ViewAuditedForTest(s, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	audited.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))
	if handlerRan {
		t.Error("an unattributable read was served")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500 — reaching the audit with no principal is a wiring fault, and a "+
			"401 would send someone to look at their credential instead of at the mount", rec.Code)
	}
	if got := viewsFor(t, s, ""); len(got) != 0 {
		t.Errorf("an unattributable view was recorded (%d rows)", len(got))
	}
}

// TestTheRecordedQueryIsCanonicalAndBounded.
//
// Canonical: a console that reorders its parameters between releases must not make yesterday's search
// look like a different one. Bounded and MARKED: the query is operator-controlled text written into an
// audit table on every request, so it is capped — and a silent truncation would be worse than the cap,
// because a reader would believe a partial record complete.
//
// Mutation: drop the sort.Strings in canonicalViewQuery → the canonical half FAILS. Return q[:max]
// without the marker → the truncation half FAILS.
func TestTheRecordedQueryIsCanonicalAndBounded(t *testing.T) {
	// FIVE parameters, not two. Go randomises map iteration, so an unsorted implementation would emit
	// the right order by luck one time in two with a pair — and a test that fails half the time is one
	// somebody deletes. With five the mutation is caught 119 times in 120.
	filter := url.Values{"since": {"1h"}, "agent": {"host-7"}, "kind": {"file"}, "limit": {"50"},
		"verified": {"true"}}
	const want = "agent=host-7&kind=file&limit=50&since=1h&verified=true"
	for i := 0; i < 8; i++ {
		if got := controlplane.CanonicalViewQueryForTest(filter); got != want {
			t.Fatalf("the recorded query is not canonical: %q, want %q — a console that reorders its "+
				"parameters between releases would make yesterday's search look like a different one", got, want)
		}
	}

	max := controlplane.MaxViewQueryLenForTest()
	long := controlplane.CanonicalViewQueryForTest(url.Values{"q": {strings.Repeat("x", max*2)}})
	if len(long) <= max {
		t.Fatalf("an over-long query rendered to %d bytes, which is not the truncation path", len(long))
	}
	if !strings.HasSuffix(long, controlplane.ViewQueryTruncatedForTest()) {
		t.Errorf("a truncated query does not say it was truncated: %q…", long[:40])
	}
	if len(long) != max+len(controlplane.ViewQueryTruncatedForTest()) {
		t.Errorf("truncated length %d, want the bound plus the marker", len(long))
	}
}

// TestTheRouteDecisionTablesAreDisjointAndReasoned.
//
// The two tables make different claims — "audited by its own handler, which knows a subject the URL does
// not carry" and "deliberately not audited". A path in both would be silently unaudited while looking
// accounted for, which is the exact failure this ticket exists to remove. And an exemption with no
// reason is a route somebody skipped rather than decided about.
//
// Mutation: add any viewAuditedInHandler key to viewAuditExempt, or blank an exemption's reason → FAILS.
func TestTheRouteDecisionTablesAreDisjointAndReasoned(t *testing.T) {
	exempt := controlplane.ViewAuditExemptForTest()
	inHandler := controlplane.ViewAuditedInHandlerForTest()

	for path := range inHandler {
		if _, both := exempt[path]; both {
			t.Errorf("%s is both audited-in-handler and exempt — one of those two statements is false, "+
				"and whichever it is, the route is unaudited while looking accounted for", path)
		}
	}
	for path, reason := range exempt {
		// A length floor, not merely non-empty: "n/a" is how a decision table becomes a list of routes
		// somebody skipped.
		if len(reason) < 40 {
			t.Errorf("%s is exempt with a reason too thin to disagree with: %q", path, reason)
		}
	}
	if len(exempt) == 0 || len(inHandler) == 0 {
		t.Fatal("a decision table is empty — the per-route decision was not made")
	}
}

// TestEveryViewAuditDecisionNamesARealRoute.
//
// The wrapper matches on the request path, so a decision recorded against a path that is not mounted —
// a typo, or a route that was renamed — is a decision about nothing. The direction of the mistake is
// safe (the real route stays audited, because unnamed means recorded) and that is exactly what makes it
// invisible: the table would claim a considered exemption while the route it meant to exempt records.
// A decision table nobody can trust is worse than no table.
//
// The mount list is read from the source by the CONSOLE-1 route-closure guard, so this stays true as
// the surface grows rather than duplicating a list that falls behind.
//
// Mutation: rename any viewAuditExempt key (e.g. "/health" → "/healthz") → this FAILS naming it.
func TestEveryViewAuditDecisionNamesARealRoute(t *testing.T) {
	mounted := map[string]bool{}
	for _, p := range mountedOperatorRoutes(t) {
		mounted[p] = true
	}
	if len(mounted) == 0 {
		t.Fatal("no mounted routes were found — this guard proves nothing")
	}
	for _, table := range []map[string]string{
		controlplane.ViewAuditExemptForTest(), controlplane.ViewAuditedInHandlerForTest(),
	} {
		for path := range table {
			if !mounted[path] {
				t.Errorf("%s carries a view-audit decision and is not a mounted route — the decision "+
					"applies to nothing, while the table reads as though somebody considered it", path)
			}
		}
	}
}

// TestPurgeViewsOlderThanDeletesPastTheCutoffOnly. Migration 007 shipped this table with no TTL and no
// purge while storing raw, non-pseudonymised operator identities.
//
// BOTH DIRECTIONS: a purge that deletes everything satisfies "old rows are gone" perfectly, and would
// destroy the accountability record it is supposed to bound.
//
// Mutation: change the WHERE to `viewed_at > $1`, or drop the WHERE → one half or the other FAILS.
func TestPurgeViewsOlderThanDeletesPastTheCutoffOnly(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	const stale, fresh = "cert:purge-stale", "cert:purge-fresh"
	if err := s.RecordView(ctx, stale, "subject-old", "e-old"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordView(ctx, fresh, "subject-new", "e-new"); err != nil {
		t.Fatal(err)
	}
	// Age the first row past the window. Backdating the row is the only way to test a window without
	// making the test wait one.
	if _, err := pool.Exec(ctx,
		`UPDATE investigation_views SET viewed_at = now() - interval '400 days' WHERE viewer = $1`,
		stale); err != nil {
		t.Fatal(err)
	}

	n, err := s.PurgeViewsOlderThan(ctx, time.Now().Add(-365*24*time.Hour))
	if err != nil {
		t.Fatalf("purging: %v", err)
	}
	if n != 1 {
		t.Errorf("purge removed %d rows, want 1", n)
	}
	if got := viewsFor(t, s, stale); len(got) != 0 {
		t.Error("a view past the retention window survived — the table stores raw operator identities " +
			"and an unbounded permanent record of everyone's reading is not a posture this product can " +
			"defend")
	}
	if got := viewsFor(t, s, fresh); len(got) != 1 {
		t.Error("a view INSIDE the window was purged — an accountability record that a purge can reach " +
			"early is one a disputed read has nothing to be checked against")
	}
}

// TestASubjectReportCountsWhoLookedAtTheSubject. The DSAR compiled every other subject-keyed store and
// omitted the one that answers the question a data-subject request most obviously asks of a view audit.
//
// The zero case is asserted too: an omitted field and a field saying "nobody looked" are different
// answers, and a report that silently drops the question is not an access report.
//
// Mutation: remove the ViewsOfSubject query from SubjectAccessReport → the non-zero half FAILS.
func TestASubjectReportCountsWhoLookedAtTheSubject(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	const watched, unwatched = "subject-watched", "subject-unwatched"
	for _, viewer := range []string{"cert:analyst-a", "cert:analyst-b"} {
		if err := s.RecordView(ctx, viewer, watched, ""); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := s.SubjectAccessReport(ctx, watched)
	if err != nil {
		t.Fatalf("compiling the subject report: %v", err)
	}
	if rep.ViewsOfSubject.Count != 2 {
		t.Errorf("the report counts %d views of the subject, want 2 — 'who has been looking at me' is the "+
			"question a data-subject request asks of a view audit", rep.ViewsOfSubject.Count)
	}
	if rep.ViewsOfSubject.FirstAt == nil || rep.ViewsOfSubject.LastAt == nil {
		t.Error("the report carries a count with no span, so the subject learns that it happened and not when")
	}

	rep, err = s.SubjectAccessReport(ctx, unwatched)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ViewsOfSubject.Count != 0 {
		t.Errorf("an unviewed subject reports %d views", rep.ViewsOfSubject.Count)
	}
}
