//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// CONSOLE-6 AGAINST THE SHIPPED BINARY.
//
// `/events` capped at 1000 rows with no cursor and no signal that more existed. Against 90-day retention
// an analyst got the top rows and had no way to reach the rest — and no way to know the rest was there.
// A truncated result that LOOKS COMPLETE is a wrong answer rather than a short one.
//
// The walk has to work over HTTP, through the real handler and the real gate, because that is where the
// cursor is parsed, refused or honoured.

type eventsPageBody struct {
	Rows []struct {
		AgentID string `json:"agent_id"`
		EventID string `json:"event_id"`
	} `json:"rows"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor"`
}

func TestAnAnalystCanPageBeyondTheCapOverHTTP(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)

	const agent, total = "agent-paging", 12
	pool := openPool(t, stack.DSN)
	for i := 0; i < total; i++ {
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified)
			 VALUES ($1,'event',$2,'\x00',true)`, agent, fmt.Sprintf("pg-ev-%03d", i)); err != nil {
			t.Fatalf("seeding row %d: %v", i, err)
		}
	}

	analyst := p.operator(t, "analyst", "paging-hunter")
	base := "https://" + addr + "/events?agent=" + agent + "&limit=5"

	// THE WALK. Every row reached, exactly once, across pages — which is the entire ticket.
	seen := map[string]int{}
	url, pages := base, 0
	for {
		var page eventsPageBody
		getOperatorJSON(t, analyst, url, &page)
		pages++
		for _, r := range page.Rows {
			seen[r.EventID]++
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Errorf("the final page offered cursor %q — a client sends it back and renders an empty "+
					"page as a real one", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("has_more with no cursor — the walk cannot continue, which is the unreachable-row " +
				"problem with extra steps")
		}
		url = base + "&cursor=" + page.NextCursor
		if pages > 10 {
			t.Fatal("the walk did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("12 rows at limit=5 completed in %d page(s) — the scenario never paged, so it proves "+
			"nothing about paging", pages)
	}
	if len(seen) != total {
		t.Fatalf("the walk saw %d distinct rows of %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %s was returned %d times across pages", id, n)
		}
	}

	// A MALFORMED CURSOR IS REFUSED over the wire, not silently served from the start.
	resp, err := analyst.Get(base + "&cursor=obviously-not-a-cursor")
	if err != nil {
		t.Fatalf("GET with a bad cursor: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a malformed cursor returned %d, want 400 — a client deep in a result set must not "+
			"silently receive page 1", resp.StatusCode)
	}
}

// CONSOLE-6b AGAINST THE SHIPPED BINARY: the alert queue, the filtered hunt and the incident list.
//
// A source-level test proves the query is right. It does not prove that the mux, the view-audit wrapper
// and the tier gate compose around it — and the cursor is parsed, refused or honoured inside exactly that
// composition. The walk therefore has to run over real HTTP with a real operator credential.
type alertPageBody struct {
	Rows []struct {
		ID        int64  `json:"id"`
		SubjectID string `json:"subject_id"`
	} `json:"rows"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor"`
}

type incidentPageBody struct {
	Rows []struct {
		ID        int64  `json:"id"`
		SubjectID string `json:"subject_id"`
	} `json:"rows"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor"`
}

func TestAnAnalystCanPageAlertsAndIncidentsOverHTTP(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)

	pool := openPool(t, stack.DSN)
	const subject, totalAlerts, totalIncidents = "sub-paging", 12, 9
	// The alerts carry NO agent_id, so the burst rule's `count(DISTINCT NULLIF(agent_id,'')) >= 1` never
	// holds for them and GET /incidents cannot raise a tenth incident out of this fixture mid-walk. The
	// incident count below is therefore exactly what was seeded.
	for i := 0; i < totalAlerts; i++ {
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at, dedup_key)
			 VALUES ($1, 0.5, 'v1', now() - make_interval(mins => $2), $3)`,
			subject, i, fmt.Sprintf("pg-alert-%03d", i)); err != nil {
			t.Fatalf("seeding alert %d: %v", i, err)
		}
	}
	for i := 0; i < totalIncidents; i++ {
		// ACKNOWLEDGED, so the burst rule's upsert cannot extend them mid-walk: this scenario is about
		// the walk composing over HTTP, not about the documented open-incident residual.
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
			 VALUES ('ueba_burst', $1, 'acknowledged', 3, 0.8, 1, now(), now() - make_interval(mins => $2))`,
			fmt.Sprintf("sub-inc-%02d", i), i); err != nil {
			t.Fatalf("seeding incident %d: %v", i, err)
		}
	}

	analyst := p.operator(t, "analyst", "paging-hunter-2")

	// Each surface walked to its end over the wire: every row once, and the last page offering nothing
	// to continue with.
	for _, surface := range []struct {
		name, base string
		want       int
	}{
		{"alerts", "https://" + addr + "/alerts?limit=5", totalAlerts},
		{"search", "https://" + addr + "/search?subject=" + subject + "&limit=5", totalAlerts},
		{"incidents", "https://" + addr + "/incidents?limit=4", totalIncidents},
	} {
		seen := map[int64]int{}
		url, pages := surface.base, 0
		for {
			var page alertPageBody // both envelopes are {rows:[{id,…}], has_more, next_cursor}
			getOperatorJSON(t, analyst, url, &page)
			pages++
			for _, r := range page.Rows {
				if surface.name != "incidents" && r.SubjectID != subject {
					continue // /alerts is unfiltered; only this scenario's rows are being counted
				}
				seen[r.ID]++
			}
			if !page.HasMore {
				if page.NextCursor != "" {
					t.Errorf("%s: the final page offered cursor %q — a client sends it back and renders "+
						"an empty page as a real one", surface.name, page.NextCursor)
				}
				break
			}
			if page.NextCursor == "" {
				t.Fatalf("%s: has_more with no cursor — the walk cannot continue, which is the "+
					"unreachable-row problem with extra steps", surface.name)
			}
			url = surface.base + "&cursor=" + page.NextCursor
			if pages > 10 {
				t.Fatalf("%s: the walk did not terminate", surface.name)
			}
		}
		if pages < 2 {
			t.Fatalf("%s: completed in %d page(s) — the scenario never paged, so it proves nothing "+
				"about paging", surface.name, pages)
		}
		if len(seen) != surface.want {
			t.Fatalf("%s: the walk saw %d distinct rows of %d", surface.name, len(seen), surface.want)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("%s: row %d was returned %d times across pages", surface.name, id, n)
			}
		}
	}

	// A CURSOR MINTED BY ONE SURFACE IS REFUSED BY ANOTHER, through the real gate and the real mux.
	// Without the version-tag namespace this returns 200 and a page about entirely different rows.
	var firstAlerts alertPageBody
	getOperatorJSON(t, analyst, "https://"+addr+"/alerts?limit=5", &firstAlerts)
	var firstIncidents incidentPageBody
	getOperatorJSON(t, analyst, "https://"+addr+"/incidents?limit=4", &firstIncidents)
	if firstAlerts.NextCursor == "" || firstIncidents.NextCursor == "" {
		t.Fatal("a surface offered no cursor to cross-present")
	}
	for _, bad := range []struct{ name, url string }{
		{"an /incidents cursor on /alerts", "https://" + addr + "/alerts?cursor=" + firstIncidents.NextCursor},
		{"an /alerts cursor on /incidents", "https://" + addr + "/incidents?cursor=" + firstAlerts.NextCursor},
		{"a malformed cursor on /alerts", "https://" + addr + "/alerts?cursor=obviously-not-a-cursor"},
		{"a malformed cursor on /incidents", "https://" + addr + "/incidents?cursor=obviously-not-a-cursor"},
	} {
		resp, err := analyst.Get(bad.url)
		if err != nil {
			t.Fatalf("GET %s: %v", bad.name, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400 — a position in another table's id space decodes to a "+
				"plausible page about the wrong rows", bad.name, resp.StatusCode)
		}
	}
}
