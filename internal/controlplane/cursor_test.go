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

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-6: keyset pagination.
//
// `/events` capped at 1000 with no cursor and no signal that more existed. Against 90-day retention an
// analyst got the top 1000 rows and had no way to reach row 1001 — and no way to know it was there. A
// truncated result that LOOKS COMPLETE is the failure, not the truncation.

// seedEvents writes n telemetry rows for one agent, oldest first, so the newest has the highest id.
func seedEvents(t *testing.T, srv *controlplane.Server, agent string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		srv.InsertFleetTelemetryForTest(t, agent, fmt.Sprintf("%s-ev-%03d", agent, i), []byte("x"), true)
	}
}

func eventsPage(t *testing.T, srv *controlplane.Server, agent, cursor string, limit int) controlplane.EventPage {
	t.Helper()
	page, err := srv.SearchTelemetryPage(context.Background(), controlplane.EventFilter{
		AgentID: agent, Limit: limit, Cursor: cursor,
	})
	if err != nil {
		t.Fatalf("SearchTelemetryPage(cursor=%q): %v", cursor, err)
	}
	return page
}

// TestPagingReachesEveryRowExactlyOnce.
//
// The whole ticket: a hunt cannot be built on "top N rows, no row N+1". Walking must reach every matching
// row, and must not repeat one — an investigator counting occurrences would get a wrong number.
//
// Mutation: use `<=` instead of `<` in the keyset predicate → the boundary row repeats → FAILS.
// Mutation: take the cursor from the probe row instead of the last kept row → a row is skipped → FAILS.
func TestPagingReachesEveryRowExactlyOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	const agent, total = "agent-keyset", 25
	seedEvents(t, srv, agent, total)

	seen := map[string]int{}
	cursor := ""
	pages := 0
	for {
		page := eventsPage(t, srv, agent, cursor, 7)
		pages++
		for _, r := range page.Rows {
			seen[r.EventID]++
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Errorf("the last page offers a continuation cursor %q — a client will send it back and "+
					"render an empty page as a real one", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("has_more is true and no cursor was offered — the walk cannot continue, which is the " +
				"unreachable-row-1001 problem with extra steps")
		}
		cursor = page.NextCursor
		if pages > 20 {
			t.Fatal("the walk did not terminate")
		}
	}

	if len(seen) != total {
		t.Fatalf("the walk saw %d distinct rows of %d — pagination that cannot reach every row is the "+
			"problem this ticket exists to fix", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %s was returned %d times — an investigator counting occurrences gets a wrong "+
				"number", id, n)
		}
	}
}

// TestATruncatedResultSaysSo.
//
// Mutation: report HasMore=false always → FAILS. This is the assertion that separates "partial" from
// "complete", and a result that looks complete is a wrong answer rather than a short one.
func TestATruncatedResultSaysSo(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	const agent = "agent-truncated"
	seedEvents(t, srv, agent, 5)

	short := eventsPage(t, srv, agent, "", 2)
	if !short.HasMore {
		t.Error("a page holding 2 of 5 rows reports itself complete — an analyst concludes the fleet " +
			"holds nothing beyond it")
	}
	if len(short.Rows) != 2 {
		t.Errorf("limit=2 returned %d rows — the over-read probe row must be discarded, or `limit` does "+
			"not mean what it says", len(short.Rows))
	}

	// AND THE NEGATIVE HALF, so this cannot pass by always reporting more.
	whole := eventsPage(t, srv, agent, "", 50)
	if whole.HasMore {
		t.Error("a page holding every matching row reports that more exist")
	}
	if len(whole.Rows) != 5 {
		t.Errorf("got %d rows, want all 5", len(whole.Rows))
	}
}

// TestAMalformedCursorIsRefusedRatherThanIgnored.
//
// Silently restarting hands page 1 to a client that believes it is on page 5: it renders duplicates and
// concludes the underlying data changed.
//
// Mutation: ignore a decode error and start from the beginning → FAILS.
func TestAMalformedCursorIsRefusedRatherThanIgnored(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)

	for _, bad := range []string{"not-base64!!", "YWJj", "djI6bm90LWEtbnVtYmVyOjE"} {
		rec := httptest.NewRecorder()
		controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
			ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/events?cursor="+bad, "hunter", "analyst"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET /events?cursor=%s = %d, want 400 — a client that believes it is deep in a "+
				"result set must not silently receive page 1", bad, rec.Code)
		}
	}
}

// TestACursorCarriesPositionAndNeverAuthority.
//
// ⚠️ THE REQUIREMENT INHERITED FROM CONSOLE-1. A cursor honoured without re-deriving the caller's
// authority lets one operator replay another's and page through rows they were never entitled to.
//
// The cursor is opaque but NOT secret, and it encodes a POSITION ONLY, so presenting someone else's
// yields their position and YOUR authority. The two halves asserted here are: (1) the encoded form
// carries no identity, role or scope; (2) the same cursor presented WITHOUT a credential is refused by
// the gate, which is what makes authority a property of the request rather than of the cursor.
func TestACursorCarriesPositionAndNeverAuthority(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	const agent = "agent-authority"
	seedEvents(t, srv, agent, 4)

	page := eventsPage(t, srv, agent, "", 2)
	if page.NextCursor == "" {
		t.Fatal("no cursor to examine")
	}

	// 1. NOTHING ABOUT THE CALLER IS IN IT. Decoded, it is a timestamp and a row id.
	decoded := controlplane.DecodeCursorForTest(t, page.NextCursor)
	for _, leak := range []string{"analyst", "admin", "cert:", "oidc:", "svc:", "role", "scope", "tier"} {
		if strings.Contains(strings.ToLower(decoded), leak) {
			t.Errorf("the cursor encodes %q (%q) — a cursor that carries authority is a capability, and "+
				"replaying someone else's becomes privilege escalation", leak, decoded)
		}
	}

	// 2. AUTHORITY IS A PROPERTY OF THE REQUEST. The same cursor, with no credential, is refused.
	anon := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/events?cursor="+page.NextCursor, nil))
	if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusForbidden {
		t.Errorf("a valid cursor with NO credential returned %d — the cursor would then be the thing "+
			"granting access, which is exactly what it must never be", anon.Code)
	}

	// 3. And with a credential it works, so the refusal above is the gate and not a broken cursor.
	ca := newOneCA(t)
	ok := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(ok, certReq(t, ca, http.MethodGet, "/events?cursor="+page.NextCursor, "hunter", "analyst"))
	if ok.Code != http.StatusOK {
		t.Fatalf("the same cursor WITH an analyst credential = %d %q; the assertion above would then "+
			"hold for a cursor that simply does not work", ok.Code, strings.TrimSpace(ok.Body.String()))
	}
}

// TestThePageSerializesItsShape — a console reads rows, has_more and next_cursor; `null` rows would need
// a nil check that is exactly the difference between "no matches" and "the read failed".
func TestThePageSerializesItsShape(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	ca := newOneCA(t)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/events?agent=nobody", "hunter", "analyst"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /events = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"rows":null`) {
		t.Errorf("an empty page serialized rows as null: %s", body)
	}
	var page controlplane.EventPage
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("parsing %q: %v", body, err)
	}
	if page.HasMore {
		t.Error("an empty page reports that more exist")
	}
	if strings.Contains(body, `"next_cursor"`) {
		t.Errorf("an empty page offers a continuation cursor: %s", body)
	}
	_ = time.Now
}
