package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// A heartbeat over embedded NATS advances the agent's last-seen — an idle agent
// that reports nothing is still distinguishable from a gone one (D16).
func TestHeartbeatUpdatesLastSeen(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	tr, err := natsx.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	before := time.Now().Add(-time.Second)
	if err := tr.PublishHeartbeat(context.Background(), &corev1.Heartbeat{
		AgentId: "agent-live", Sequence: 1, ObservedAt: timestamppb.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool {
		_, ok, _ := srv.LastSeen(context.Background(), "agent-live")
		return ok
	})
	seen, ok, err := srv.LastSeen(context.Background(), "agent-live")
	if err != nil || !ok {
		t.Fatalf("last-seen not recorded: ok=%v err=%v", ok, err)
	}
	if seen.Before(before) {
		t.Errorf("last-seen %v is before the heartbeat", seen)
	}
	// An unknown agent is not found.
	if _, ok, _ := srv.LastSeen(context.Background(), "nobody"); ok {
		t.Error("an unknown agent was reported as seen")
	}
}

// Overdue end to end: one agent heartbeats now, another's last-seen is in the
// past; only the stale one is overdue.
func TestOverdueEndToEnd(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	tr, _ := natsx.Connect(url)
	defer tr.Close()
	// Two agents check in now.
	for _, id := range []string{"agent-fresh", "agent-stale"} {
		_ = tr.PublishHeartbeat(context.Background(), &corev1.Heartbeat{AgentId: id, Sequence: 1, ObservedAt: timestamppb.Now()})
	}
	waitFor(t, func() bool {
		_, ok, _ := srv.LastSeen(context.Background(), "agent-stale")
		if !ok {
			return false
		}
		_, ok2, _ := srv.LastSeen(context.Background(), "agent-fresh")
		return ok2
	})

	// Backdate agent-stale's rows so it appears silent.
	if _, err := pool.Exec(context.Background(),
		`UPDATE fleet_telemetry SET received_at = now() - interval '1 hour' WHERE agent_id = 'agent-stale'`); err != nil {
		t.Fatal(err)
	}

	overdue, err := srv.Overdue(context.Background(), 10*time.Minute, time.Now())
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
		t.Error("agent-fresh (just seen) should NOT be overdue")
	}
}
