package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-14 — SAVED SEARCHES.
//
// A SOC's hunts are institutional knowledge, and they were living in people's shell history. The cost is
// not the typing: it is that the hunt which found something last quarter is not repeatable by whoever is
// on shift tonight, and a detection only one analyst can perform is not a detection the team has.

// THE HEADLINE: a saved search returns exactly what the equivalent typed query returns.
//
// That equality is the whole product promise. If the saved form could diverge from the live one, a saved
// hunt would be a query that resembles the one an analyst tested — and nobody would find out which,
// because both return rows.
//
// Mutation (have RunSavedSearch build its own filter instead of re-parsing through the surface's parser
// and calling the same Search*): the two result sets differ → FAIL.
func TestASavedSearchReturnsWhatTheTypedQueryReturns(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_saved_%d", now.UnixNano())

	for i, risk := range []float64{0.95, 0.30, 0.88} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'v1','agent-a',$3)`, subject, risk, now.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	query := "subject=" + subject + "&min_risk=0.8"
	if err := srv.SaveSearch(ctx, controlplane.SavedSearch{
		Name: "high-risk-for-subject", Surface: controlplane.SurfaceAlerts, Query: query,
		Description: "the hunt that found it last quarter",
	}, "cert:alice"); err != nil {
		t.Fatalf("saving: %v", err)
	}

	surface, results, err := srv.RunSavedSearch(ctx, "high-risk-for-subject")
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if surface != controlplane.SurfaceAlerts {
		t.Fatalf("surface = %q, want %q", surface, controlplane.SurfaceAlerts)
	}
	saved, ok := results.([]controlplane.PeerAlert)
	if !ok {
		t.Fatalf("results are %T, want []PeerAlert", results)
	}

	// The same filter, typed live.
	typed, err := srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{SubjectID: subject, MinRisk: 0.8})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != len(typed) || len(saved) != 2 {
		t.Fatalf("saved search returned %d, the typed query %d; want both 2 — a saved hunt that "+
			"resembles the one an analyst tested is worse than none, because both return rows and "+
			"nobody finds out which they are looking at", len(saved), len(typed))
	}
	for i := range saved {
		if saved[i].ID != typed[i].ID {
			t.Fatalf("result %d differs: saved id %d, typed id %d", i, saved[i].ID, typed[i].ID)
		}
	}
}

// A SEARCH THAT CANNOT RUN IS REFUSED WHEN IT IS SAVED, not when it is needed.
//
// This is what makes the feature more than a JSON blob store. The analyst is standing there and can fix
// it now; discovering it during the incident it was saved for is the failure mode.
//
// Mutation (skip validateSearch in SaveSearch): the bad searches are accepted → FAIL.
func TestABadSearchIsRefusedAtSaveTime(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	for _, tc := range []struct{ name, surface, query, why string }{
		{"bad since", controlplane.SurfaceAlerts, "since=yesterday",
			"an unparseable timestamp would 400 at the endpoint"},
		{"bad limit", controlplane.SurfaceLogs, "limit=lots",
			"a non-numeric limit is refused by the live parser"},
		{"bad field filter", controlplane.SurfaceLogs, "field=nocolon",
			"a field filter with no colon is refused by the live parser"},
		{"unknown surface", "dashboards", "limit=10",
			"a surface outside the closed set has no parser and no endpoint"},
		{"no name", controlplane.SurfaceAlerts, "limit=10",
			"a nameless search cannot be recalled by anyone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sv := controlplane.SavedSearch{Name: "s-" + tc.name, Surface: tc.surface, Query: tc.query}
			if tc.name == "no name" {
				sv.Name = "   "
			}
			err := srv.SaveSearch(ctx, sv, "cert:alice")
			if err == nil {
				t.Fatalf("accepted a search that cannot run: %s", tc.why)
			}
			if !errors.Is(err, controlplane.ErrBadSavedSearch) && !errors.Is(err, controlplane.ErrUnknownSurface) {
				t.Fatalf("error = %v, want a typed save-refusal an API can turn into a 400", err)
			}
		})
	}

	// And a valid one saves, so the refusals above are not "nothing is ever accepted".
	if err := srv.SaveSearch(ctx, controlplane.SavedSearch{
		Name: "ok", Surface: controlplane.SurfaceEvents, Query: "limit=10",
	}, "cert:alice"); err != nil {
		t.Fatalf("a valid search was refused: %v", err)
	}
}

// REPLACING A SEARCH KEEPS WHO INTRODUCED IT.
//
// "Who wrote this hunt" and "who last touched it" are different questions, and overwriting the first
// with the second loses the answer to both — the reviewer who wants to ask about the hunt's intent ends
// up asking whoever adjusted a limit.
//
// Mutation (set created_by = EXCLUDED.created_by in the DO UPDATE): the author becomes bob → FAIL.
func TestReplacingASearchKeepsItsOriginalAuthor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	base := controlplane.SavedSearch{Name: "shared", Surface: controlplane.SurfaceEvents, Query: "limit=10"}
	if err := srv.SaveSearch(ctx, base, "cert:alice"); err != nil {
		t.Fatal(err)
	}
	base.Query = "limit=50"
	if err := srv.SaveSearch(ctx, base, "cert:bob"); err != nil {
		t.Fatal(err)
	}

	got, err := srv.SavedSearchByName(ctx, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedBy != "cert:alice" {
		t.Errorf("created_by = %q, want operator:alice — the person who introduced a hunt is a "+
			"different question from who last adjusted it", got.CreatedBy)
	}
	if got.UpdatedBy != "cert:bob" {
		t.Errorf("updated_by = %q, want operator:bob", got.UpdatedBy)
	}
	if got.Query != "limit=50" {
		t.Errorf("query = %q, want the replacement", got.Query)
	}
}

// DELETING SOMETHING THAT IS NOT THERE IS NOT A SUCCESS.
//
// Reporting "deleted" for a name that was never saved lets an operator believe a hunt is gone when a
// differently-spelled one is still there and still running.
//
// Mutation (return nil regardless of RowsAffected): the second delete reports success → FAIL.
func TestDeletingAMissingSearchIsNotReportedAsSuccess(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	if err := srv.SaveSearch(ctx, controlplane.SavedSearch{
		Name: "doomed", Surface: controlplane.SurfaceEvents, Query: "limit=10",
	}, "cert:alice"); err != nil {
		t.Fatal(err)
	}
	if err := srv.DeleteSavedSearch(ctx, "doomed"); err != nil {
		t.Fatalf("deleting an existing search: %v", err)
	}
	if err := srv.DeleteSavedSearch(ctx, "doomed"); !errors.Is(err, controlplane.ErrNoSuchSearch) {
		t.Fatalf("second delete = %v, want ErrNoSuchSearch — 'deleted' when nothing was deleted lets "+
			"an operator believe a hunt is gone that is still running", err)
	}
	if _, _, err := srv.RunSavedSearch(ctx, "doomed"); !errors.Is(err, controlplane.ErrNoSuchSearch) {
		t.Fatalf("running a deleted search = %v, want ErrNoSuchSearch", err)
	}
}

// THE ENDPOINTS ARE MOUNTED, AND WRITING IS A HIGHER TIER THAN READING.
//
// A handler is not a feature until something routes to it. And the read/write split has to be on
// separate PATHS, because the role gate is per-path: mounting the write on the read's path grants either
// every analyst the ability to rewrite the team's hunts or nobody the ability to read them.
//
// Mutation A (drop a route registration): 404 → FAIL.
// Mutation B (gate /searches/save at analyst): the analyst's save succeeds → FAIL.
func TestTheSavedSearchEndpointsAreMountedAndTiered(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)

	responder := clientWith(t, ca, "bob", "responder")
	analyst := clientWith(t, ca, "carol", "analyst")

	save := func(c *http.Client, name string) int {
		t.Helper()
		resp, err := c.Post("https://"+addr+"/searches/save?name="+name+
			"&surface=events&query=limit%3D10", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := save(responder, "team-hunt"); code != http.StatusOK {
		t.Fatalf("responder save = %d, want 200 — the endpoint is unreachable, which is a handler "+
			"with tests and no route", code)
	}
	if code := save(analyst, "analyst-hunt"); code == http.StatusOK {
		t.Fatalf("an ANALYST wrote a saved search (%d) — a saved search is a tool the whole team will "+
			"run and trust, so authoring one is the responder tier", code)
	}

	// The analyst can still LIST and RUN, which is the point of the split.
	for _, path := range []string{"/searches", "/searches/run?name=team-hunt"} {
		resp, err := analyst.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusOK {
			t.Fatalf("analyst GET %s = %d, want 200 — running a saved search reaches exactly the "+
				"surfaces that tier already reads, so refusing it protects nothing", path, code)
		}
	}

	// A run of something that is not saved is 404, not an empty result set that reads as a finding.
	resp, err := analyst.Get("https://" + addr + "/searches/run?name=never-saved")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("running an unsaved name = %d, want 404 — an empty result would read as 'the hunt "+
			"found nothing'", resp.StatusCode)
	}
}

// TestASavedSearchCannotCaptureAContinuationCursor — CONSOLE-6b, and the defect this test exists for is
// a FREEZE, not a bad parameter.
//
// `parseAlertFilter` and `parseEventFilter` both read `cursor=`, and both are the parsers `validateSearch`
// accepts a saved search with and `runResolvedSearch` executes it through. So
// `POST /searches/save?surface=alerts&query=subject%3DX%26cursor%3D<valid>` was ACCEPTED and PERSISTED,
// and every later run applied a boundary from the instant the hunt was saved. Cursors do not expire, so
// it never self-heals: the hunt permanently excludes everything newer, keeps returning rows, and returns
// a truncated result as the answer. That is exactly the outcome RunSavedSearch's own doc comment calls
// "the worst outcome available".
//
// The EVENTS half is a PRE-EXISTING defect shipped in D481 (event_search.go sets f.Cursor and
// SurfaceEvents dispatches to it); the ALERTS half is one CONSOLE-6b would have introduced. Both are
// fixed here and both are asserted, because a fix on the surface the author happened to be editing is
// how the other half survives.
//
// Mutation: drop the rejectStoredCursor call from validateSearch → the save halves return nil → FAILS.
// Mutation: drop it from runResolvedSearch → the already-stored search runs frozen → the run half FAILS.
// Mutation: refuse `cursor` unconditionally in rejectStoredCursor rather than only when non-empty → the
// POSITIVE halves below FAIL, so a blanket refusal cannot pass this test.
func TestASavedSearchCannotCaptureAContinuationCursor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_frozen_%d", now.UnixNano())

	// Real cursors, minted by the real walks — a MALFORMED one is already refused by the surface
	// parsers, so a test using one would pass without this fix and prove nothing.
	seedAlerts(t, pool, subject, 4, now.Add(-time.Hour))
	alertCur := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 2}).NextCursor
	agent := fmt.Sprintf("agent-frozen-%d", now.UnixNano())
	for i := 0; i < 4; i++ {
		srv.InsertFleetTelemetryForTest(t, agent, fmt.Sprintf("frozen-ev-%d", i), []byte("x"), true)
	}
	eventCur := eventsPage(t, srv, agent, "", 2).NextCursor
	if alertCur == "" || eventCur == "" {
		t.Fatalf("no cursor to freeze with (alerts=%q events=%q)", alertCur, eventCur)
	}

	// 1. THE POSITIVE HALF FIRST: the same hunts, without a cursor, save fine. Without this a blanket
	// refusal of everything would satisfy the assertions below.
	for _, ok := range []struct{ name, surface, query string }{
		{"live-alerts", controlplane.SurfaceAlerts, "subject=" + subject + "&min_risk=0.1"},
		{"live-events", controlplane.SurfaceEvents, "agent=" + agent},
	} {
		if err := srv.SaveSearch(ctx, controlplane.SavedSearch{
			Name: ok.name, Surface: ok.surface, Query: ok.query,
		}, "cert:alice"); err != nil {
			t.Fatalf("saving the cursor-free %s hunt failed: %v — the refusals below would then hold "+
				"for queries that simply do not save", ok.surface, err)
		}
	}

	// 2. THE REFUSAL, ON BOTH SURFACES.
	for _, frozen := range []struct{ name, surface, query string }{
		{"frozen-alerts", controlplane.SurfaceAlerts, "subject=" + subject + "&cursor=" + alertCur},
		{"frozen-events", controlplane.SurfaceEvents, "agent=" + agent + "&cursor=" + eventCur},
	} {
		err := srv.SaveSearch(ctx, controlplane.SavedSearch{
			Name: frozen.name, Surface: frozen.surface, Query: frozen.query,
		}, "cert:alice")
		if !errors.Is(err, controlplane.ErrBadSavedSearch) {
			t.Errorf("saving a %s hunt carrying a valid cursor returned %v, want ErrBadSavedSearch — a "+
				"stored cursor freezes the hunt at the instant it was saved, forever, silently",
				frozen.surface, err)
		}
		if _, err := srv.SavedSearchByName(ctx, frozen.name); !errors.Is(err, controlplane.ErrNoSuchSearch) {
			t.Errorf("the refused %s hunt was persisted anyway (%v)", frozen.surface, err)
		}
	}

	// 3. AND A SEARCH ALREADY IN THE TABLE — one written before this check existed, which is the
	// population that has actually been frozen — FAILS LOUDLY when it is run, rather than quietly
	// serving the boundary it captured. Inserted directly, because SaveSearch now refuses it.
	execSQL(t, pool,
		`INSERT INTO saved_searches (name, surface, query, description, created_by, updated_by)
		 VALUES ('legacy-frozen', $1, $2, '', 'cert:legacy', 'cert:legacy')`,
		controlplane.SurfaceAlerts, "subject="+subject+"&cursor="+alertCur)
	if _, _, err := srv.RunSavedSearch(ctx, "legacy-frozen"); !errors.Is(err, controlplane.ErrBadSavedSearch) {
		t.Errorf("running a stored search that carries a cursor returned %v, want ErrBadSavedSearch — "+
			"it would otherwise go on answering with everything older than the moment it was saved, "+
			"and the truncation is the part nobody sees", err)
	}
	// The same search with the cursor removed runs, so the failure above is the cursor and not the row.
	execSQL(t, pool, `UPDATE saved_searches SET query = $1 WHERE name = 'legacy-frozen'`,
		"subject="+subject)
	if _, _, err := srv.RunSavedSearch(ctx, "legacy-frozen"); err != nil {
		t.Errorf("the same stored search without its cursor failed to run: %v", err)
	}
}
