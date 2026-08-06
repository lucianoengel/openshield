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
	// AND THE REFUSAL IS COUNTED (D483). It used to write the 500 and discard the error: no counter, no
	// log line, nothing anywhere except the status the operator was staring at.
	//
	// Mutation: remove the viewAuditRefused call from the record-failure branch → this FAILS.
	if n := s.ViewAuditFailures.Load(); n != 1 {
		t.Errorf("a read refused for an unrecordable view counted %d failures, want 1", n)
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
	// A LITERAL CEILING (D483). Every assertion below is expressed in terms of `max`, so setting
	// maxViewQueryLen to 1_000_000 keeps all of them green while the write amplification the bound
	// exists to stop is gone — the value is operator-controlled text written into an audit table on
	// every request. Stated as a range rather than an equality so an ordinary tuning does not fail a
	// test that has nothing to say about it.
	//
	// Mutation: set maxViewQueryLen to 1_000_000 → this FAILS.
	if max < 64 || max > 4096 {
		t.Fatalf("the recorded-query bound is %d bytes. Below ~64 it truncates ordinary searches into "+
			"uselessness; above a few KB it is not a bound — an authenticated insider controls this text "+
			"and writes it once per request", max)
	}

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

	// AND A TRUNCATED QUERY STILL DECODES (D483). The stored form is percent-encoded, so a cut at an
	// arbitrary byte can land inside a `%XX` escape and leave "%" or "%4" at the end — at which point a
	// reader that URL-decodes the audit record gets an error rather than a partial query. That is not a
	// bounded record, it is an unreadable one, in the column whose entire job is to say what was
	// searched for.
	//
	// The value is built so the cut MUST land mid-escape: every character escapes to three bytes, so at
	// least one offset in each group of three is inside one. All three offsets are exercised.
	//
	// Mutation: return q[:maxViewQueryLen] without escapeBoundary → at least one of these FAILS.
	for pad := 0; pad < 3; pad++ {
		v := url.Values{"q": {strings.Repeat("é", max)}}
		if pad > 0 {
			v["a"] = []string{strings.Repeat("z", pad)}
		}
		got := controlplane.CanonicalViewQueryForTest(v)
		body := strings.TrimSuffix(got, controlplane.ViewQueryTruncatedForTest())
		if _, err := url.ParseQuery(body); err != nil {
			t.Errorf("a truncated query does not decode (pad=%d): %v — …%q", pad, err, body[len(body)-8:])
		}
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
	if err := s.RecordView(ctx, controlplane.ViewRecord{
		Viewer: stale, SubjectFilter: "subject-old", EventID: "e-old", Route: "/cases",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordView(ctx, controlplane.ViewRecord{
		Viewer: fresh, SubjectFilter: "subject-new", EventID: "e-new", Route: "/cases",
	}); err != nil {
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
		if err := s.RecordView(ctx, controlplane.ViewRecord{
			Viewer: viewer, SubjectFilter: watched, Route: "/cases",
		}); err != nil {
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

// D483 — THE HARDENING CASES.
//
// Everything above proves the wrapper. These prove the five routes the wrapper deliberately does NOT
// cover, the failure path it takes when it cannot record, and the two places the record said something
// untrue about itself.

// TestTheDSARRecordsItsOwnAccessWithItsRouteAndSubject.
//
// `/subject` is the single most sensitive read on the surface — it compiles everything the platform
// holds about one named human — and it had NO test asserting that it records at all. It was covered only
// by the fact that `RecordView` was called somewhere in its handler.
//
// And it wrote route=”. Migration 053 declares that value to mean "recorded before CONSOLE-5, no route
// captured", so a query for who ran DSARs returned nothing, forever, while the rows sat in the table
// looking like history.
//
// Mutation: drop `Route` from recordRequestView (or revert the handler to the 4-argument RecordView) →
// the route assertion FAILS. Mutation: delete the recording call → the count FAILS.
func TestTheDSARRecordsItsOwnAccessWithItsRouteAndSubject(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	const cn = "dsar-officer"
	const principal = "cert:" + cn
	const subject = "subject-dsar-audited"
	officer := grantOperator(t, s, ca, cn, controlplane.RolePrivacyOfficer)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM investigation_views WHERE viewer = $1`, principal)
	})

	rec := httptest.NewRecorder()
	controlplane.RequirePrivacyOfficerForTestHandler(s, s.OperatorReadHandler()).
		ServeHTTP(rec, officer("/subject?id="+subject))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /subject = %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	got := viewsFor(t, s, principal)
	if len(got) != 1 {
		t.Fatalf("the DSAR recorded %d views, want exactly 1 — a dossier compiled on a named individual "+
			"that leaves no trace of who compiled it is the read this whole control exists for", len(got))
	}
	if got[0].Route != "/subject" {
		t.Errorf("the DSAR recorded route %q. Migration 053 says '' means 'recorded before CONSOLE-5, no "+
			"route captured', so a live handler writing it makes today's dossier reads indistinguishable "+
			"from legacy rows and `WHERE route='/subject'` answers nothing", got[0].Route)
	}
	if got[0].SubjectFilter != subject || got[0].EventID != "dsar" {
		t.Errorf("the DSAR recorded subject=%q event=%q, want %q/dsar — the subject is the whole reason "+
			"this route records in its own handler rather than in the wrapper",
			got[0].SubjectFilter, got[0].EventID, subject)
	}
}

// TestARefusedAuditedReadIsCountedAndNamedByTheHealthReport.
//
// The refusal is correct and it takes the WHOLE console read surface down at once. Both failure branches
// used to write a 500 and return: the error was discarded, no counter moved, stderr said nothing. And
// `/health` is EXEMPT from recording, so it went on answering 200 with `degraded: false` — the one
// surface built to say whether the process works was the only one that could not see the outage.
//
// DRIVEN THROUGH THE NO-PRINCIPAL BRANCH, over a database that is perfectly REACHABLE. That is the
// point: every other fact on the report is fine and the console is still dark. Failing the record by
// closing the pool would make `degraded` true through the unreachable-database problem instead, and the
// case would prove nothing about the view audit. (The pool-failure branch's counter is asserted in
// TestAReadThatCannotBeRecordedIsRefusedAndTheHandlerNeverRuns, which already has a broken pool.)
//
// Mutation: remove the viewAuditRefused call from the no-principal branch → the counter half FAILS.
// Mutation: delete the ViewAuditFailures branch from healthProblems → the health half FAILS.
func TestARefusedAuditedReadIsCountedAndNamedByTheHealthReport(t *testing.T) {
	s := controlplane.New(requireDB(t))

	var handlerRan bool
	rec := httptest.NewRecorder()
	controlplane.ViewAuditedForTest(s, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))
	if handlerRan || rec.Code != http.StatusInternalServerError {
		t.Fatalf("the fixture did not reach the refusal branch: %d, handler ran=%v", rec.Code, handlerRan)
	}
	if n := s.ViewAuditFailures.Load(); n != 1 {
		t.Errorf("a refused read incremented the failure counter %d times, want 1 — without it the only "+
			"evidence of a dark console is the 500 the operator happens to be looking at", n)
	}

	got := healthVia(t, s)
	if !got.DatabaseReachable {
		t.Fatal("this fixture needs a reachable database, or `degraded` proves nothing about the audit")
	}
	if got.ViewAuditFailures == 0 || !got.Degraded {
		t.Fatalf("health reports view_audit_failures=%d degraded=%v while audited reads are being "+
			"refused", got.ViewAuditFailures, got.Degraded)
	}
	// `Degraded` is the weak half and is checked only as a sanity condition: this fixture's ledger has
	// never been anchored, so the report is degraded either way. THE NAMING IS THE CLAIM — a tile that
	// goes red without saying why sends an operator to look at the database.
	var named bool
	for _, p := range got.Problems {
		if strings.Contains(p, "view audit") {
			named = true
		}
	}
	if !named {
		t.Errorf("the health report is degraded and no problem names the view audit: %v — a tile that "+
			"goes red without saying why sends an operator to look at the database", got.Problems)
	}
}

// TestRunningASavedSearchRecordsTheFilterNotTheName.
//
// `/searches/run?name=team-hunt` was audited by the wrapper, so the recorded query was `name=team-hunt`.
// That name is a MUTABLE, DELETABLE pointer — SaveSearch is upsert-on-name and /searches/delete is a
// hard delete, both at RESPONDER tier, which is below the tier that reviews the audit. An audit row
// whose meaning a colleague can rewrite afterwards bounds nothing.
//
// The subject half is the sharper one: without lifting the saved search's own `subject=`, saving a
// subject-naming search and running it by name is a way to read someone's file WITHOUT appearing in that
// person's access report.
//
// Mutation: move /searches/run back out of viewAuditedInHandler, or drop the resolved-query branch →
// the query assertions FAIL. Drop the SubjectFilter lift → the DSAR-join assertion FAILS.
func TestRunningASavedSearchRecordsTheFilterNotTheName(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)
	ctx := context.Background()

	const cn = "saved-runner"
	const principal = "cert:" + cn
	const name = "hunt-d483"
	const subject = "subject-saved-search"
	grantOperator(t, s, ca, cn, controlplane.RoleAnalyst)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigation_views WHERE viewer = $1`, principal)
		_, _ = pool.Exec(ctx, `DELETE FROM saved_searches WHERE name = $1`, name)
	})
	if err := s.SaveSearch(ctx, controlplane.SavedSearch{
		Name: name, Surface: controlplane.SurfaceAlerts, Query: "subject=" + subject + "&limit=5",
	}, principal); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/searches/run?name="+name, cn, "agent"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /searches/run = %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	got := viewsFor(t, s, principal)
	if len(got) != 1 {
		t.Fatalf("running a saved search recorded %d views, want exactly 1", len(got))
	}
	if got[0].Route != "/searches/run" {
		t.Errorf("recorded route %q", got[0].Route)
	}
	if !strings.Contains(got[0].Query, "subject%3D"+subject) {
		t.Errorf("the recorded query is %q and does not carry the filter that selected the rows — "+
			"migration 053 says this column IS that filter, and a name a responder can redefine or "+
			"delete is not it", got[0].Query)
	}
	if !strings.Contains(got[0].Query, "surface=alerts") {
		t.Errorf("the recorded query %q does not say which store was read", got[0].Query)
	}
	if got[0].SubjectFilter != subject {
		t.Errorf("the recorded subject is %q, want %q — otherwise saving a subject-naming search and "+
			"running it by name reads someone's file without appearing in their access report",
			got[0].SubjectFilter, subject)
	}
}

// TestAnUnresolvableSavedSearchIsStillRecorded. The attempt is what is worth recording; whether it found
// anything is not the audit's business. The 404 path is the one an operator probing names would take.
//
// Mutation: move the recording after the resolve error is returned → this FAILS.
func TestAnUnresolvableSavedSearchIsStillRecorded(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	const cn = "saved-prober"
	const principal = "cert:" + cn
	grantOperator(t, s, ca, cn, controlplane.RoleAnalyst)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM investigation_views WHERE viewer = $1`, principal)
	})

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/searches/run?name=never-saved", cn, "agent"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /searches/run on a missing name = %d, want 404", rec.Code)
	}
	got := viewsFor(t, s, principal)
	if len(got) != 1 || got[0].Route != "/searches/run" {
		t.Fatalf("probing saved-search names recorded %d views (%+v) — an operator enumerating the "+
			"team's hunts by guessing names would leave nothing behind", len(got), got)
	}
}

// TestASubjectReportSeparatesTheSubjectsOwnAccessRequests.
//
// `/subject` records its own access BEFORE compiling the report, so the DSAR counts itself: ask twice
// and the number grows by one each time, with no way to tell your own requests from an investigator's.
//
// The breakdown, not a subtraction: an access request IS an operator reading the subject's file, and
// quietly dropping it would hide a real access to make a number less confusing.
//
// Mutation: delete the FILTER clause from the DSAR views query → the breakdown reads 0 and this FAILS.
func TestASubjectReportSeparatesTheSubjectsOwnAccessRequests(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	const subject = "subject-dsar-breakdown"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigation_views WHERE subject_filter = $1`, subject)
	})
	// Two investigators looked; one access request was made.
	for _, v := range []controlplane.ViewRecord{
		{Viewer: "cert:analyst-x", SubjectFilter: subject, Route: "/cases"},
		{Viewer: "cert:analyst-y", SubjectFilter: subject, Route: "/search"},
		{Viewer: "cert:officer-z", SubjectFilter: subject, Route: "/subject", EventID: "dsar"},
	} {
		if err := s.RecordView(ctx, v); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := s.SubjectAccessReport(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ViewsOfSubject.Count != 3 {
		t.Errorf("the report counts %d views, want 3", rep.ViewsOfSubject.Count)
	}
	if rep.ViewsThatWereAccessRequests != 1 {
		t.Errorf("the report attributes %d of those to the subject's own access requests, want 1 — "+
			"without the split, asking twice makes the number rise and the subject cannot tell their own "+
			"requests from an investigator's", rep.ViewsThatWereAccessRequests)
	}
}
