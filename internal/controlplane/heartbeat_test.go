package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

// The dead-man's-switch as a pure function: a long-silent agent is overdue, a
// recent one is not. No DB, no infrastructure — the logic that decides "someone
// should look" must be trivially verifiable.
func TestDeadMansSwitch(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	threshold := 5 * time.Minute
	statuses := []controlplane.AgentStatus{
		{AgentID: "fresh", LastSeen: now.Add(-1 * time.Minute)},
		{AgentID: "stale", LastSeen: now.Add(-30 * time.Minute)},
		{AgentID: "edge-under", LastSeen: now.Add(-4 * time.Minute)},
		{AgentID: "edge-over", LastSeen: now.Add(-6 * time.Minute)},
	}
	overdue := controlplane.OverdueAgents(statuses, threshold, now)

	got := map[string]bool{}
	for _, s := range overdue {
		got[s.AgentID] = true
		if !s.Overdue {
			t.Errorf("%s in the overdue list but Overdue=false", s.AgentID)
		}
	}
	want := map[string]bool{"stale": true, "edge-over": true}
	for id := range want {
		if !got[id] {
			t.Errorf("%s should be overdue (silent past %s)", id, threshold)
		}
	}
	for _, id := range []string{"fresh", "edge-under"} {
		if got[id] {
			t.Errorf("%s should NOT be overdue", id)
		}
	}
}

// seedRoster enrolls an agent (adds it to agent_identities) so liveness tracks it (SEC-3
// derives the roster from enrolled agents). A minimal public key is enough for the roster.
func seedRoster(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, agentID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agent_identities (agent_id, public_key) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		agentID, []byte("roster-key")); err != nil {
		t.Fatal(err)
	}
}

// seedTelemetry inserts a fleet_telemetry row with the given verified flag and time.
func seedTelemetryRow(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, agentID string, verified bool, receivedAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified, received_at)
		 VALUES ($1,'event','e','\x00',$2,$3)`, agentID, verified, receivedAt); err != nil {
		t.Fatal(err)
	}
}

// SEC-3: LastSeen counts only VERIFIED telemetry — an unsigned publisher cannot refresh an
// agent's last-seen — and an unknown agent is not found.
func TestLastSeenCountsVerifiedOnly(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()

	seedRoster(t, pool, "agent-live")
	seedTelemetryRow(t, pool, "agent-live", true, now.Add(-time.Second))
	if _, ok, err := srv.LastSeen(ctx, "agent-live"); err != nil || !ok {
		t.Fatalf("verified last-seen not found: ok=%v err=%v", ok, err)
	}

	// An agent seen ONLY via unverified telemetry is NOT counted as seen — the SEC-3 core:
	// a forging publisher cannot keep it alive.
	seedRoster(t, pool, "agent-forged")
	seedTelemetryRow(t, pool, "agent-forged", false, now)
	if _, ok, _ := srv.LastSeen(ctx, "agent-forged"); ok {
		t.Error("an agent seen only via UNVERIFIED telemetry was reported as seen (SEC-3)")
	}

	// An unknown agent is not found (and this is absence, not an error).
	if _, ok, err := srv.LastSeen(ctx, "nobody"); ok || err != nil {
		t.Errorf("unknown agent: ok=%v err=%v, want not-found, no error", ok, err)
	}
}

// SEC-11: a DB error must surface as an ERROR, not masquerade as agent absence — a down
// database reading as "agent unknown" would silently hide the whole fleet.
func TestLastSeenDBErrorIsNotAbsence(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	seedRoster(t, pool, "agent-x")
	seedTelemetryRow(t, pool, "agent-x", true, time.Now())
	pool.Close() // force a DB failure on the next query
	if _, ok, err := srv.LastSeen(context.Background(), "agent-x"); err == nil {
		t.Errorf("LastSeen on a closed pool returned ok=%v err=nil — a DB error masqueraded as absence (SEC-11)", ok)
	}
}

// SEC-3: Overdue derives from the roster and verified telemetry — a stale agent is overdue,
// a fresh one is not, an enrolled-but-NEVER-seen agent is overdue (roster fix), and an agent
// kept "fresh" only by UNVERIFIED telemetry is still overdue (the dead-man's-switch holds).
func TestOverdueVerifiedAndRoster(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	now := time.Now()

	seedRoster(t, pool, "agent-fresh")
	seedTelemetryRow(t, pool, "agent-fresh", true, now)
	seedRoster(t, pool, "agent-stale")
	seedTelemetryRow(t, pool, "agent-stale", true, now.Add(-time.Hour))
	seedRoster(t, pool, "agent-silent") // enrolled, never sent → must be overdue
	// A compromised agent kept "alive" ONLY by a forger's unverified telemetry:
	seedRoster(t, pool, "agent-compromised")
	seedTelemetryRow(t, pool, "agent-compromised", false, now) // unverified "fresh" — must NOT rescue it

	overdue, err := srv.Overdue(context.Background(), 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range overdue {
		ids[s.AgentID] = true
	}
	if !ids["agent-stale"] {
		t.Error("agent-stale (silent 1h) should be overdue")
	}
	if ids["agent-fresh"] {
		t.Error("agent-fresh (verified, just seen) should NOT be overdue")
	}
	if !ids["agent-silent"] {
		t.Error("agent-silent (enrolled, never seen) should be overdue — the roster fix")
	}
	if !ids["agent-compromised"] {
		t.Error("agent-compromised (only UNVERIFIED telemetry) should be overdue — the dead-man's-switch (SEC-3)")
	}
}
