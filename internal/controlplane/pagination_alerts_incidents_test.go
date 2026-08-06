package controlplane_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-6b: the walk reaches /alerts, /search and /incidents.
//
// CONSOLE-6 fixed /events and left the three surfaces a console spends most of its time on carrying the
// identical defect: a capped read served as a bare array, with no signal that anything was left behind.
// An analyst reads the alert queue and concludes the fleet raised exactly that many alerts. That is a
// wrong answer that looks authoritative, not a short one.
//
// Both tables already carry `id BIGSERIAL PRIMARY KEY`, so `(detected_at, id)` and `(last_seen, id)` are
// unique and monotone and no migration was needed. What the ticket warned about — a keyset walk over a
// NON-UNIQUE ordering silently losing rows — is real anyway, and is pinned below by a deliberate tie
// fixture rather than argued away.

// seedAlerts writes n alerts for one subject, oldest first, one minute apart, so the newest has both the
// latest detected_at and the highest id.
func seedAlerts(t *testing.T, pool *pgxpool.Pool, subject string, n int, base time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		execSQL(t, pool,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at, dedup_key)
			 VALUES ($1, 0.5, 'v1', $2, $3)`,
			subject, base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("%s-%03d", subject, i))
	}
}

// seedWalkIncident writes one incident directly, so its state and last_seen are exactly what the test says
// rather than whatever a correlation pass would have computed.
func seedWalkIncident(t *testing.T, pool *pgxpool.Pool, subject, state string, lastSeen time.Time) {
	t.Helper()
	execSQL(t, pool,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
		 VALUES ('ueba_burst', $1, $2, 3, 0.8, 1, $3, $3)`, subject, state, lastSeen)
}

func alertPage(t *testing.T, srv *controlplane.Server, f controlplane.AlertFilter) controlplane.AlertPage {
	t.Helper()
	page, err := srv.SearchPeerAlertsPage(context.Background(), f)
	if err != nil {
		t.Fatalf("SearchPeerAlertsPage(cursor=%q): %v", f.Cursor, err)
	}
	return page
}

func incidentPage(t *testing.T, srv *controlplane.Server, limit int, cursor string) controlplane.IncidentPage {
	t.Helper()
	page, err := srv.RecentIncidentsPage(context.Background(), limit, cursor)
	if err != nil {
		t.Fatalf("RecentIncidentsPage(cursor=%q): %v", cursor, err)
	}
	return page
}

// TestTheAlertWalkReachesEveryAlertExactlyOnce.
//
// The queue an analyst triages from must be walkable to its end: a hunt cannot be built on "the top N
// alerts, and no way to know about N+1". Reaching a row twice is just as wrong — an analyst counting
// occurrences of a subject gets an inflated number.
//
// Mutation: `<=` instead of `<` in the keyset predicate → the boundary alert repeats → FAILS.
// Mutation: build the cursor from the probe row instead of the last kept row → an alert is skipped → FAILS.
// Mutation: report HasMore from the raw row count rather than the over-read → the walk never ends → FAILS.
func TestTheAlertWalkReachesEveryAlertExactlyOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	const subject, total = "sub_walk", 23
	seedAlerts(t, pool, subject, total, time.Now().UTC().Add(-time.Duration(total)*time.Minute))

	seen := map[int64]int{}
	cursor, pages := "", 0
	for {
		page := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 6, Cursor: cursor})
		pages++
		for _, a := range page.Rows {
			seen[a.ID]++
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Errorf("the last page offers cursor %q — a client sends it back and renders an empty "+
					"page as a real one", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("has_more with no cursor: the walk cannot continue, which is the unreachable-row " +
				"problem with extra steps")
		}
		cursor = page.NextCursor
		if pages > 20 {
			t.Fatal("the walk did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("%d alerts at limit=6 completed in %d page(s) — the case never paged", total, pages)
	}
	if len(seen) != total {
		t.Fatalf("the walk saw %d distinct alerts of %d — a queue that cannot be walked to its end is "+
			"the defect this change exists to fix", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("alert %d was returned %d times — an analyst counting occurrences gets a wrong "+
				"number", id, n)
		}
	}
}

// TestTheIncidentWalkReachesEveryIncidentExactlyOnce — the same guarantee on the incident list.
//
// Mutation: `<=` instead of `<` → the boundary incident repeats → FAILS.
// Mutation: ORDER BY last_seen DESC without id, cursor from the last kept row → with distinct
// timestamps this still passes, which is exactly why the tie fixture below is a separate test.
func TestTheIncidentWalkReachesEveryIncidentExactlyOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	base := time.Now().UTC().Add(-3 * time.Hour)
	const total = 17
	for i := 0; i < total; i++ {
		seedWalkIncident(t, pool, fmt.Sprintf("sub_inc_%02d", i), "acknowledged", base.Add(time.Duration(i)*time.Minute))
	}

	seen := map[int64]int{}
	cursor, pages := "", 0
	for {
		page := incidentPage(t, srv, 5, cursor)
		pages++
		for _, inc := range page.Rows {
			seen[inc.ID]++
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Errorf("the last page offers cursor %q", page.NextCursor)
			}
			break
		}
		cursor = page.NextCursor
		if pages > 20 {
			t.Fatal("the walk did not terminate")
		}
	}
	if len(seen) != total {
		t.Fatalf("the walk saw %d distinct incidents of %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("incident %d was returned %d times across pages", id, n)
		}
	}
}

// TestRowsSharingATimestampAreNotLostByTheWalk.
//
// ⚠️ THE FIXTURE THIS EXTENSION SPECIFICALLY NEEDS, and the reason it is built deliberately: a walk over
// rows with DISTINCT timestamps passes against a boundary that ignores the row id. Only a TIE exposes it.
// One detector pass writes several alerts for one subject stamped at the same instant; and an incident's
// last_seen is `max(detected_at)` over its subject's alerts, so two subjects whose newest alerts landed in
// the same pass tie exactly. Ties are the normal case here, not a contrivance. (They are NOT produced by
// a materialization pass stamping now() — no writer of last_seen uses now(); an earlier version of this
// comment said otherwise.)
//
// Mutation: drop `, id` from the alert ORDER BY and use `detected_at < $n` as the boundary → the walk
// steps past the whole tied group after returning one of them, and every other tied row becomes
// permanently unreachable → FAILS, seeing 2 of the 5 alerts (one of the four tied rows, then the older
// one below them).
// The same mutation on the incident query → FAILS the same way, seeing 1 of the 3 tied incidents.
func TestRowsSharingATimestampAreNotLostByTheWalk(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)

	// FOUR alerts at the EXACT same instant, plus one older so the walk has somewhere to go afterwards.
	tie := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond) // pg stores microseconds
	const subject = "sub_tied"
	for i := 0; i < 4; i++ {
		execSQL(t, pool,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at, dedup_key)
			 VALUES ($1, 0.5, 'v1', $2, $3)`, subject, tie, fmt.Sprintf("tie-%d", i))
	}
	execSQL(t, pool,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at, dedup_key)
		 VALUES ($1, 0.5, 'v1', $2, 'tie-older')`, subject, tie.Add(-time.Minute))

	seen := map[int64]int{}
	cursor := ""
	for i := 0; i < 12; i++ {
		page := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 1, Cursor: cursor})
		for _, a := range page.Rows {
			seen[a.ID]++
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 5 {
		t.Errorf("the walk saw %d of 5 alerts, four of which share one detected_at — a boundary that "+
			"cannot tell tied rows apart steps over the whole group and loses it for the rest of the "+
			"walk, silently", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("alert %d returned %d times", id, n)
		}
	}

	// AND THE SAME FOR INCIDENTS, whose last_seen ties are produced by one materialization pass.
	same := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		seedWalkIncident(t, pool, fmt.Sprintf("sub_tie_inc_%d", i), "acknowledged", same)
	}
	incSeen := map[int64]int{}
	cursor = ""
	for i := 0; i < 10; i++ {
		page := incidentPage(t, srv, 1, cursor)
		for _, inc := range page.Rows {
			incSeen[inc.ID]++
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(incSeen) != 3 {
		t.Errorf("the walk saw %d of 3 incidents sharing one last_seen", len(incSeen))
	}
	for id, n := range incSeen {
		if n != 1 {
			t.Errorf("incident %d returned %d times", id, n)
		}
	}
}

// TestATruncatedAlertOrIncidentReadSaysSo.
//
// The whole defect in one assertion: "partial" and "complete" must not look alike.
//
// Mutation: hardcode HasMore=false → the truncation halves FAIL.
// Mutation: return the over-read probe row instead of discarding it → the len() assertions FAIL, because
// `limit` would no longer mean what it says.
// Mutation: hardcode HasMore=true → the NEGATIVE halves below FAIL. Without them this test would pass
// against a page that simply always claims more exist.
func TestATruncatedAlertOrIncidentReadSaysSo(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	const subject = "sub_trunc"
	seedAlerts(t, pool, subject, 5, time.Now().UTC().Add(-time.Hour))
	for i := 0; i < 5; i++ {
		seedWalkIncident(t, pool, fmt.Sprintf("sub_trunc_inc_%d", i), "acknowledged",
			time.Now().UTC().Add(-time.Duration(i+1)*time.Minute))
	}

	short := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 2})
	if !short.HasMore {
		t.Error("a page holding 2 of 5 alerts reports itself complete — an analyst concludes the queue " +
			"holds nothing beyond it")
	}
	if len(short.Rows) != 2 {
		t.Errorf("limit=2 returned %d alerts — the over-read probe row must be discarded", len(short.Rows))
	}
	whole := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 50})
	if whole.HasMore || whole.NextCursor != "" {
		t.Error("a page holding every matching alert reports that more exist")
	}

	shortInc := incidentPage(t, srv, 2, "")
	if !shortInc.HasMore {
		t.Error("a page holding 2 of 5 incidents reports itself complete")
	}
	if len(shortInc.Rows) != 2 {
		t.Errorf("limit=2 returned %d incidents", len(shortInc.Rows))
	}
	wholeInc := incidentPage(t, srv, 50, "")
	if wholeInc.HasMore || wholeInc.NextCursor != "" {
		t.Error("a page holding every incident reports that more exist")
	}
}

// TestAMalformedAlertOrIncidentCursorIsRefusedRatherThanIgnored.
//
// Silently restarting hands page 1 to a client that believes it is on page 5: it renders duplicates and
// concludes the underlying data changed under it.
//
// Mutation: ignore a decode error and start from the beginning → FAILS.
func TestAMalformedAlertOrIncidentCursorIsRefusedRatherThanIgnored(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())

	bad := []string{"not-base64!!", "YWJj", "YTE6bm90LWEtbnVtYmVyOjE"} // last: "a1:not-a-number:1"
	for _, route := range []string{"/alerts", "/search", "/incidents"} {
		for _, c := range bad {
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, route+"?cursor="+c, "hunter", "analyst"))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("GET %s?cursor=%s = %d, want 400 — a client that believes it is deep in a "+
					"result set must not silently receive page 1", route, c, rec.Code)
			}
		}
	}
}

// TestACursorIsRefusedByASurfaceItWasNotMintedFor.
//
// ⚠️ THE GUARD WITH NO ANALOGUE IN CONSOLE-6's SUITE, and the reason the version tag is a namespace
// rather than decoration. All three cursors encode the same shape — a timestamp and an int64 — so
// without a discriminator an /events cursor presented to /alerts DECODES SUCCESSFULLY and serves a page
// that is wrong but entirely plausible: row-identity corruption dressed up as a normal result.
//
// Mutation: strip the `parts[0] != version` check out of decodeKeyset → every cross-surface case here
// returns 200 with a wrong-but-plausible page → FAILS. Note that the malformed-cursor test above still
// PASSES against that same mutation: those bytes are badly shaped, these are validly shaped for the
// wrong table. That difference is the whole point of this test.
func TestACursorIsRefusedByASurfaceItWasNotMintedFor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())

	// Mint one real cursor per surface, from the real walk each surface offers.
	const subject = "sub_ns"
	seedAlerts(t, pool, subject, 4, time.Now().UTC().Add(-time.Hour))
	for i := 0; i < 4; i++ {
		seedWalkIncident(t, pool, fmt.Sprintf("sub_ns_inc_%d", i), "acknowledged",
			time.Now().UTC().Add(-time.Duration(i+1)*time.Minute))
	}
	for i := 0; i < 4; i++ {
		srv.InsertFleetTelemetryForTest(t, "agent-ns", fmt.Sprintf("ns-ev-%d", i), []byte("x"), true)
	}
	alertCur := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 2}).NextCursor
	incCur := incidentPage(t, srv, 2, "").NextCursor
	evCur := eventsPage(t, srv, "agent-ns", "", 2).NextCursor
	if alertCur == "" || incCur == "" || evCur == "" {
		t.Fatalf("a surface offered no cursor to test with (alerts=%q incidents=%q events=%q)",
			alertCur, incCur, evCur)
	}

	get := func(path string) int {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, path, "hunter", "analyst"))
		return rec.Code
	}

	// THE POSITIVE HALF FIRST, so a blanket refusal cannot pass this test: each cursor works on the
	// surface that minted it.
	for _, ok := range []struct{ path, name string }{
		{"/alerts?cursor=" + alertCur, "alert cursor on /alerts"},
		{"/search?subject=" + subject + "&cursor=" + alertCur, "alert cursor on /search"},
		{"/incidents?cursor=" + incCur, "incident cursor on /incidents"},
		{"/events?agent=agent-ns&cursor=" + evCur, "event cursor on /events"},
	} {
		if code := get(ok.path); code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 — the refusals below would then hold for cursors that simply "+
				"do not work anywhere", ok.name, code)
		}
	}

	// AND THE REFUSAL: a position in one table's id space is not a position in another's.
	for _, bad := range []struct{ path, name string }{
		{"/alerts?cursor=" + evCur, "an /events cursor on /alerts"},
		{"/alerts?cursor=" + incCur, "an /incidents cursor on /alerts"},
		{"/search?cursor=" + evCur, "an /events cursor on /search"},
		{"/incidents?cursor=" + alertCur, "an /alerts cursor on /incidents"},
		{"/incidents?cursor=" + evCur, "an /events cursor on /incidents"},
		{"/events?cursor=" + alertCur, "an /alerts cursor on /events"},
	} {
		if code := get(bad.path); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400 — it decodes to a plausible position in the WRONG table, so the "+
				"page served would look complete and be about other rows entirely", bad.name, code)
		}
	}
}

// TestAnAlertCursorCarriesPositionAndNeverAuthority.
//
// ⚠️ THE REQUIREMENT INHERITED FROM CONSOLE-1, carried onto the new surfaces unchanged. A cursor honoured
// without re-deriving the caller's authority lets one operator replay another's and page through rows
// they were never entitled to. The namespace tag added by this change names a TABLE, never a scope — and
// this test is what keeps that true.
//
// Mutation: encode the operator's role into the cursor → the decoded-form assertion FAILS. Asserting on
// the opaque string instead would pass against any encoding that merely looked scrambled.
// Mutation: serve /alerts outside the tier gate → the no-credential assertion FAILS.
func TestAnAlertCursorCarriesPositionAndNeverAuthority(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	const subject = "sub_authority"
	seedAlerts(t, pool, subject, 4, time.Now().UTC().Add(-time.Hour))
	seedWalkIncident(t, pool, "sub_auth_inc_a", "acknowledged", time.Now().UTC().Add(-2*time.Minute))
	seedWalkIncident(t, pool, "sub_auth_inc_b", "acknowledged", time.Now().UTC().Add(-3*time.Minute))

	alertCur := alertPage(t, srv, controlplane.AlertFilter{SubjectID: subject, Limit: 2}).NextCursor
	incCur := incidentPage(t, srv, 1, "").NextCursor
	if alertCur == "" || incCur == "" {
		t.Fatal("no cursor to examine")
	}

	// 1. NOTHING ABOUT THE CALLER IS IN EITHER. Decoded, each is a timestamp and a row id.
	for _, decoded := range []string{
		controlplane.DecodeAlertCursorForTest(t, alertCur),
		controlplane.DecodeIncidentCursorForTest(t, incCur),
	} {
		for _, leak := range []string{"analyst", "admin", "cert:", "oidc:", "svc:", "role", "scope", "tier"} {
			if strings.Contains(strings.ToLower(decoded), leak) {
				t.Errorf("the cursor encodes %q (%q) — a cursor that carries authority is a capability, "+
					"and replaying someone else's becomes privilege escalation", leak, decoded)
			}
		}
	}

	// 2. AUTHORITY IS A PROPERTY OF THE REQUEST. The same cursors, with no credential, are refused.
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())
	for _, path := range []string{"/alerts?cursor=" + alertCur, "/incidents?cursor=" + incCur} {
		anon := httptest.NewRecorder()
		gate.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, path, nil))
		if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusForbidden {
			t.Errorf("GET %s with NO credential returned %d — the cursor would then be the thing granting "+
				"access, which is exactly what it must never be", path, anon.Code)
		}
	}

	// 3. And with a credential they work, so the refusals above are the gate and not broken cursors.
	ca := newOneCA(t)
	for _, path := range []string{"/alerts?cursor=" + alertCur, "/incidents?cursor=" + incCur} {
		ok := httptest.NewRecorder()
		gate.ServeHTTP(ok, certReq(t, ca, http.MethodGet, path, "hunter", "analyst"))
		if ok.Code != http.StatusOK {
			t.Fatalf("GET %s WITH an analyst credential = %d %q", path, ok.Code,
				strings.TrimSpace(ok.Body.String()))
		}
	}
}

// TestTheAlertAndIncidentPagesSerializeTheirShape — a console reads rows, has_more and next_cursor.
// `null` rows would need a nil check that is exactly the difference between "no matches" and "the read
// failed", and an empty next_cursor is a value a client will send back.
//
// Mutation: drop the `page.Rows == nil` guard → the rows:null assertion FAILS.
// Mutation: drop `omitempty` from NextCursor → the "no cursor on a complete page" assertion FAILS.
func TestTheAlertAndIncidentPagesSerializeTheirShape(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())

	for _, route := range []string{"/alerts", "/search?subject=nobody", "/incidents"} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, route, "hunter", "analyst"))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %q", route, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		body := rec.Body.String()
		if strings.Contains(body, `"rows":null`) {
			t.Errorf("GET %s serialized an empty page's rows as null: %s", route, body)
		}
		if strings.Contains(body, `"next_cursor"`) {
			t.Errorf("GET %s on an empty result offers a continuation cursor: %s", route, body)
		}
		var page struct {
			Rows    []json.RawMessage `json:"rows"`
			HasMore bool              `json:"has_more"`
		}
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatalf("parsing %s response %q: %v", route, body, err)
		}
		if page.HasMore {
			t.Errorf("GET %s on an empty result reports that more exist", route)
		}
	}
}

// TestAWalkOverIncidentsKeepsSettledHistoryWhileOpenOnesMove.
//
// ⚠️ THE RESIDUAL, PINNED. /incidents is not /events wearing a different column name: `incidents` rows in
// state='open' are UPSERTED in place — MaterializeIncidents pushes last_seen forward, from this route's
// own handler and from the leader's background loop, with no regard for anyone's walk. An open incident
// not yet reached can therefore be bumped ahead of the boundary and be absent from the rest of that walk.
//
// That is ACCEPTED (a snapshot was ruled out of scope for all keyset pagination here) and it is bounded:
// once acknowledged, the upsert's `WHERE state='open'` conflict target stops matching, so triaged
// history — what a deep walk exists to read — is immutable and must never be lost. This test holds that
// line: acceptable staleness must not be allowed to become silent loss.
//
// Mutation: make the walk resume from the FIRST row of the page rather than the last → the bumped row is
// no longer the only one missing and the acknowledged incidents are hit twice → FAILS.
// Mutation: have MaterializeIncidents stop updating last_seen → the "it resurfaces at the top of a fresh
// walk" assertion FAILS, so the second half cannot pass vacuously against a bump that never happened.
func TestAWalkOverIncidentsKeepsSettledHistoryWhileOpenOnesMove(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// Settled history, deepest in the walk — these must be reached whatever else moves.
	seedWalkIncident(t, pool, "sub_settled_1", "acknowledged", now.Add(-50*time.Minute))
	seedWalkIncident(t, pool, "sub_settled_2", "acknowledged", now.Add(-40*time.Minute))
	// Open incidents nearer the top; sub_bumped is the one that will move mid-walk.
	seedWalkIncident(t, pool, "sub_bumped", "open", now.Add(-30*time.Minute))
	seedWalkIncident(t, pool, "sub_open_b", "open", now.Add(-20*time.Minute))
	seedWalkIncident(t, pool, "sub_open_a", "open", now.Add(-10*time.Minute))

	// The alerts that will make correlation extend sub_bumped's OPEN incident to a much later last_seen.
	for i := 0; i < 3; i++ {
		execSQL(t, pool,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at, dedup_key)
			 VALUES ('sub_bumped', 0.9, 'v1', 'agent-bump', $1, $2)`,
			now.Add(-time.Minute), fmt.Sprintf("bump-%d", i))
	}

	// Page 1 of the walk: the two newest open incidents. sub_bumped has NOT been reached yet.
	first := incidentPage(t, srv, 2, "")
	if len(first.Rows) != 2 || !first.HasMore {
		t.Fatalf("page 1 = %d rows (has_more=%v), want 2 with more to come", len(first.Rows), first.HasMore)
	}
	for _, inc := range first.Rows {
		if inc.SubjectID == "sub_bumped" {
			t.Fatal("the fixture reached sub_bumped on page 1, so nothing is being bumped ahead of the " +
				"walk and the rest of this test would prove nothing")
		}
	}

	// MID-WALK, the thing that actually happens in production: correlation runs (here from a call, in
	// production also from the leader's loop) and pushes an unvisited OPEN incident's last_seen forward.
	if _, err := srv.MaterializeIncidents(ctx, controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}, now); err != nil {
		t.Fatalf("materializing mid-walk: %v", err)
	}

	// Finish the walk from where page 1 left off.
	seen := map[string]int{}
	for _, inc := range first.Rows {
		seen[inc.SubjectID]++
	}
	cursor := first.NextCursor
	for i := 0; i < 10 && cursor != ""; i++ {
		page := incidentPage(t, srv, 2, cursor)
		for _, inc := range page.Rows {
			seen[inc.SubjectID]++
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}

	// THE GUARANTEE: settled history is reached, exactly once, regardless of what moved.
	for _, sub := range []string{"sub_settled_1", "sub_settled_2"} {
		if seen[sub] != 1 {
			t.Errorf("acknowledged incident %s was seen %d times in a walk during which OTHER rows were "+
				"updated — immutable history must be reached exactly once, or a walk silently loses the "+
				"record it exists to read", sub, seen[sub])
		}
	}

	// THE RESIDUAL, stated as behaviour rather than left to be discovered: the bumped OPEN incident moved
	// above the boundary and so is not in the remainder of this walk...
	if seen["sub_bumped"] != 0 {
		t.Logf("sub_bumped was reached %d time(s) — harmless, but the documented residual assumed it "+
			"would not be; check whether the upsert still moves last_seen", seen["sub_bumped"])
	}
	// ...and it is STALENESS, NOT LOSS: a fresh walk finds it, at the top, because it just absorbed a
	// burst. Without this half, the assertion above would be satisfied by an incident that had vanished.
	fresh := incidentPage(t, srv, 10, "")
	found := false
	for _, inc := range fresh.Rows {
		if inc.SubjectID == "sub_bumped" {
			found = true
			if inc.LastSeen.Before(now.Add(-5 * time.Minute)) {
				t.Errorf("sub_bumped's last_seen is %s — correlation did not move it, so the mid-walk "+
					"bump this test is built on never happened", inc.LastSeen)
			}
		}
	}
	if !found {
		t.Error("a fresh walk does not find the bumped incident at all — that is silent LOSS rather " +
			"than the documented staleness, and the whole reason this residual was acceptable")
	}
}

// TestTheRecomputedIncidentRuleOffersNoContinuationAndRefusesACursor.
//
// ⚠️ THE REQUIREMENT THAT SHIPPED WITH NO TEST. CONSOLE-6b's delta wrote "a read whose order is
// recomputed per call MUST NOT offer continuation" and asserted it nowhere, so a later change adding
// `next_cursor` to this branch would have violated a written requirement with the whole suite green.
//
// It covers three things that were all wrong on this branch:
//
//  1. NO CONTINUATION IS OFFERED. `?rule=cross_domain` is a live GROUP BY over a rolling window: "the row
//     after this one" is not defined across a set that is re-aggregated per request, so a cursor into it
//     would be a position in something that no longer exists.
//  2. A CURSOR IS REFUSED, NOT IGNORED. It used to answer 200 and page 1 — the same route and the same
//     parameter that 400s on the burst branch, which is one URL with two behaviours, in a function whose
//     own doc comment claims every parameter is fail-loud.
//  3. ONE ENVELOPE. This branch answered a BARE ARRAY while the burst branch answered an object, so a
//     console decoding `body.rows` got `undefined` here and rendered an empty list while incidents
//     existed — a wrong answer that looks complete, on the surface this change exists to make honest. Go
//     turns that into a loud unmarshal error; the browser PLAT-1 is being built for does not.
//
// Mutation: drop the cursor check from crossDomainIncidents → the refusal half returns 200 → FAILS.
// Mutation: add a `next_cursor` field to CrossDomainPage and populate it → the no-continuation half FAILS.
// Mutation: go back to writing the bare slice → the rows half decodes zero incidents → FAILS.
// The POSITIVE half (a cursor-free request returns 200 with a real incident in `rows`) is what stops a
// blanket 400, or an always-empty envelope, from passing any of the above.
func TestTheRecomputedIncidentRuleOffersNoContinuationAndRefusesACursor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())
	now := time.Now().UTC()

	// A real cross-domain incident: two domains for one entity inside the window.
	const subject = "sub-xdr-recomputed"
	recordTechAlert(t, srv, "dlp", subject, now.Add(-4*time.Minute), "T1552")
	recordTechAlert(t, srv, "hips", subject, now.Add(-2*time.Minute), "T1218")

	const base = "/incidents?rule=cross_domain&min_domains=2&window=10m"
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, path, "hunter", "analyst"))
		return rec
	}

	// 1 + 3. The read works, answers in the SAME envelope as the walkable branch, and offers nothing to
	// continue with.
	rec := get(base)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %q", base, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	body := rec.Body.String()
	var page controlplane.CrossDomainPage
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("the cross-domain branch does not answer in the incident envelope (%v): %s", err, body)
	}
	if len(page.Rows) == 0 {
		t.Fatalf("the fixture raised no cross-domain incident, so the assertions below would hold "+
			"against an empty response and prove nothing: %s", body)
	}
	if page.HasMore {
		t.Errorf("an uncapped per-call aggregation reports that more rows exist: %s", body)
	}
	// Asserted on the RAW BODY, not on a struct field: a struct with no cursor field cannot report one
	// no matter what the handler writes, so decoding first and checking the decoded value would be
	// vacuous — the mutation this is aimed at is somebody ADDING the field. (The fixture subject is named
	// so it does not itself contain the substring; the first draft did, and this assertion failed against
	// correct code, which is the cheap version of the same lesson.)
	if strings.Contains(body, "cursor") {
		t.Errorf("the recomputed rule offers a continuation: %s — a client would walk it and believe "+
			"the walk meant something, when the set is re-aggregated on every request", body)
	}

	// 2. And a cursor is a 400 here, exactly as it is on the walkable branch — including a REAL incident
	// cursor, which decodes perfectly well and is still not a position in this result set.
	seedWalkIncident(t, pool, "sub_xdr_cur_a", "acknowledged", now.Add(-time.Minute))
	seedWalkIncident(t, pool, "sub_xdr_cur_b", "acknowledged", now.Add(-2*time.Minute))
	realCursor := incidentPage(t, srv, 1, "").NextCursor
	if realCursor == "" {
		t.Fatal("no real incident cursor to cross-present")
	}
	for _, c := range []string{realCursor, "obviously-not-a-cursor", "YWJj"} {
		if code := get(base + "&cursor=" + c).Code; code != http.StatusBadRequest {
			t.Errorf("GET %s&cursor=%s = %d, want 400 — answering page 1 to a client that believes it "+
				"is continuing a walk is the same silent wrong answer on the same route the burst "+
				"branch already refuses", base, c, code)
		}
	}
}

// TestARefusedIncidentsRequestWritesNothing.
//
// GET /incidents is a read that WRITES: MaterializeIncidents upserts each subject's open incident and can
// INSERT one, which pages the SOC. It used to run BEFORE `limit` was validated, and CONSOLE-6b's cursor
// check inherited that ordering — so a request that then answered 400 had already mutated the database
// and possibly woken someone. A rejected request must have no effects; that is what "rejected" means, and
// on this route the effect is a pager.
//
// Mutation: move the MaterializeIncidents call back above the limit/cursor checks → each refused request
// raises the incident anyway → FAILS.
// The POSITIVE half (the same fixture DOES raise an incident once a well-formed request arrives) is what
// stops this passing against a rule that simply never matches.
func TestARefusedIncidentsRequestWritesNothing(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	gate := controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler())
	now := time.Now().UTC()

	// Three alerts from one agent inside the default window: exactly what the burst rule raises on.
	const subject = "sub_refused_write"
	for i := 0; i < 3; i++ {
		execSQL(t, pool,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at, dedup_key)
			 VALUES ($1, 0.9, 'v1', 'agent-refused', $2, $3)`,
			subject, now.Add(-time.Duration(i)*time.Minute), fmt.Sprintf("refused-%d", i))
	}
	incidentsFor := func() int {
		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM incidents WHERE subject_id = $1`, subject).Scan(&n); err != nil {
			t.Fatalf("counting incidents: %v", err)
		}
		return n
	}

	for _, bad := range []string{
		"/incidents?limit=abc",                  // pre-existing: a malformed limit
		"/incidents?limit=0",                    // pre-existing: a non-positive limit
		"/incidents?cursor=obviously-not-valid", // CONSOLE-6b: a malformed cursor
	} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, bad, "hunter", "analyst"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400", bad, rec.Code)
		}
		if n := incidentsFor(); n != 0 {
			t.Fatalf("GET %s answered 400 and left %d incident(s) behind — a refused request that "+
				"still correlates has already paged whoever is on call for a request the server "+
				"declined to serve", bad, n)
		}
	}

	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/incidents", "hunter", "analyst"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /incidents = %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if n := incidentsFor(); n != 1 {
		t.Fatalf("a well-formed read raised %d incidents from a fixture built to raise one — the "+
			"refusals above would then prove nothing about the write being skipped", n)
	}
}

// TestReMaterializingWithNoNewAlertsMovesNothing.
//
// ⚠️ THE FACT THE ACCEPTED RESIDUAL RESTS ON, and it was not the one the design assumed. /incidents
// re-materializes on EVERY page of a walk, which reads like it would shove every open incident above the
// walk boundary each time. It does not: `last_seen = EXCLUDED.last_seen` is `max(detected_at)` over the
// subject's alerts, and NO writer of that column uses now(). A pass that finds no new alerts rewrites the
// value it already stored. So the mid-walk residual is bounded by live detection, not by walk depth —
// narrower than the design argued, which is what makes accepting it reasonable rather than convenient.
//
// It is asserted rather than reasoned about because it is a property of a SQL string that a future
// "touch updated_at properly" edit could flip without any test noticing.
//
// Mutation: `last_seen = now()` in MaterializeIncidents' DO UPDATE → the unchanged assertion FAILS.
// Mutation: stop updating last_seen at all → the "a new alert DOES move it" half FAILS, so the first half
// cannot pass vacuously against a column nothing writes.
func TestReMaterializingWithNoNewAlertsMovesNothing(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}

	const subject = "sub_idempotent"
	for i := 0; i < 3; i++ {
		execSQL(t, pool,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at, dedup_key)
			 VALUES ($1, 0.9, 'v1', 'agent-idem', $2, $3)`,
			subject, now.Add(-time.Duration(i+10)*time.Minute), fmt.Sprintf("idem-%d", i))
	}
	lastSeen := func() time.Time {
		var ts time.Time
		if err := pool.QueryRow(ctx,
			`SELECT last_seen FROM incidents WHERE subject_id = $1`, subject).Scan(&ts); err != nil {
			t.Fatalf("reading last_seen: %v", err)
		}
		return ts.UTC()
	}

	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatalf("first materialization: %v", err)
	}
	first := lastSeen()

	// A LATER `now`, no new alerts — the walk's second page, in effect.
	if _, err := srv.MaterializeIncidents(ctx, rule, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("second materialization: %v", err)
	}
	if again := lastSeen(); !again.Equal(first) {
		t.Errorf("last_seen moved from %s to %s with no new alerts — every page of a walk would then "+
			"push every open incident above the boundary, and the accepted residual would be unbounded "+
			"rather than bounded by live detection", first, again)
	}

	// AND A NEW ALERT DOES move it, so the assertion above is about idempotence and not about a dead
	// column.
	execSQL(t, pool,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at, dedup_key)
		 VALUES ($1, 0.9, 'v1', 'agent-idem', $2, 'idem-new')`, subject, now.Add(-time.Minute))
	if _, err := srv.MaterializeIncidents(ctx, rule, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("third materialization: %v", err)
	}
	if moved := lastSeen(); !moved.After(first) {
		t.Errorf("last_seen is still %s after a newer alert arrived — correlation is not tracking "+
			"max(detected_at), so the idempotence asserted above is vacuous", moved)
	}
}
