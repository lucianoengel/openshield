package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-1: the event search filters the fleet aggregate by agent, kind, time window and
// verified-only, is bounded, and returns newest-first. The verified filter and the bound are
// the load-bearing guards (an investigator must be able to exclude self-asserted telemetry,
// and an uncapped query is a memory vector).
func TestSearchTelemetry(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	seed := func(agent, kind, eventID string, verified bool, ago time.Duration) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified, received_at)
			 VALUES ($1,$2,$3,'\x00',$4,$5)`, agent, kind, eventID, verified, base.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}

	seed("agent-a", "event", "ev-1", true, 1*time.Minute)
	seed("agent-a", "decision", "ev-1", true, 2*time.Minute)
	seed("agent-a", "event", "ev-2", false, 3*time.Minute) // UNVERIFIED (legacy self-asserted)
	seed("agent-b", "event", "ev-3", true, 4*time.Minute)
	seed("agent-a", "event", "ev-old", true, 3*time.Hour) // outside a 1h window

	// Filter by agent: only agent-a's rows.
	got, err := srv.SearchTelemetry(ctx, controlplane.EventFilter{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if e.AgentID != "agent-a" {
			t.Errorf("agent filter leaked %q", e.AgentID)
		}
	}
	if len(got) != 4 {
		t.Errorf("agent-a rows = %d, want 4", len(got))
	}
	// Newest first.
	if len(got) >= 2 && got[0].ReceivedAt.Before(got[1].ReceivedAt) {
		t.Errorf("results not newest-first: %v before %v", got[0].ReceivedAt, got[1].ReceivedAt)
	}

	// Filter by kind.
	dec, _ := srv.SearchTelemetry(ctx, controlplane.EventFilter{AgentID: "agent-a", Kind: "decision"})
	if len(dec) != 1 || dec[0].Kind != "decision" {
		t.Errorf("kind=decision for agent-a = %+v, want 1 decision row", dec)
	}

	// VerifiedOnly excludes the self-asserted ev-2.
	ver, _ := srv.SearchTelemetry(ctx, controlplane.EventFilter{AgentID: "agent-a", VerifiedOnly: true})
	for _, e := range ver {
		if !e.Verified {
			t.Errorf("verified-only returned an unverified row: %+v", e)
		}
		if e.EventID == "ev-2" {
			t.Errorf("verified-only leaked the self-asserted ev-2")
		}
	}
	if len(ver) != 3 {
		t.Errorf("verified agent-a rows = %d, want 3 (ev-2 excluded)", len(ver))
	}

	// Time window: last hour excludes ev-old.
	win, _ := srv.SearchTelemetry(ctx, controlplane.EventFilter{AgentID: "agent-a", Since: base.Add(-time.Hour)})
	for _, e := range win {
		if e.EventID == "ev-old" {
			t.Errorf("since-window leaked the out-of-window ev-old")
		}
	}
	if len(win) != 3 {
		t.Errorf("agent-a within 1h = %d, want 3 (ev-old excluded)", len(win))
	}

	// event id.
	byEvent, _ := srv.SearchTelemetry(ctx, controlplane.EventFilter{EventID: "ev-1"})
	if len(byEvent) != 2 {
		t.Errorf("event ev-1 rows = %d, want 2 (the event and its decision)", len(byEvent))
	}
}
