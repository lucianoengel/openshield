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
