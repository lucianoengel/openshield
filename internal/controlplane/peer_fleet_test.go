package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// runServerPeer starts a server with server-side peer-UEBA ENABLED (D54). The
// long cooldown makes every test's fast burst a single rising edge.
func runServerPeer(t *testing.T, url string, threshold float64, cooldown time.Duration) *controlplane.Server {
	t.Helper()
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.EnablePeerUEBA(threshold, cooldown)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)
	return srv
}

// peerAlertCount returns how many peer_alerts rows exist for a subject.
func peerAlertCount(t *testing.T, subject string) int {
	t.Helper()
	pool := mustPoolCP(t)
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM peer_alerts WHERE subject_id=$1`, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// eventFor builds an Event whose behaviour is attributed to a pseudonymous subject.
func eventFor(id, subject string) *corev1.Event {
	return &corev1.Event{EventId: id, Subject: &corev1.Subject{PseudonymousId: subject}}
}

// An enabled server, fed a verified OUTLIER over NATS, raises a peer alert for the
// outlier subject and NONE for a typical subject — the cross-entity signal, end to
// end over the real telemetry path.
func TestPeerAlertOnVerifiedOutlier(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServerPeer(t, url, 0.5, time.Hour)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-peer")
	ctx := context.Background()

	// A population: three typical subjects with a little activity each...
	for _, s := range []string{"p1", "p2", "p3"} {
		for i := 0; i < 3; i++ {
			if err := pub.PublishEvent(ctx, eventFor("e", s)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// ...and one OUTLIER far above its peers.
	for i := 0; i < 40; i++ {
		if err := pub.PublishEvent(ctx, eventFor("e", "outlier")); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, func() bool { return srv.PeerAlerts.Load() >= 1 })
	if got := peerAlertCount(t, "outlier"); got < 1 {
		t.Fatalf("no peer alert for the outlier subject (%d) — the cross-fleet signal did not fire", got)
	}
	for _, s := range []string{"p1", "p2", "p3"} {
		if got := peerAlertCount(t, s); got != 0 {
			t.Errorf("typical subject %q raised %d peer alerts — peer risk is not discriminating", s, got)
		}
	}
}

// Unverified telemetry (bad signature) records NO peer alert and does not move the
// baseline: observePeer runs only AFTER verification, so a rejected outlier is
// never observed and never contributes to peer risk.
func TestPeerAlertIgnoresUnverified(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServerPeer(t, url, 0.5, time.Hour)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Enroll a real agent to establish a small verified population...
	pub := signedAgent(t, srv, conn, "agent-mix")
	ctx := context.Background()
	for _, s := range []string{"p1", "p2"} {
		for i := 0; i < 3; i++ {
			_ = pub.PublishEvent(ctx, eventFor("e", s))
		}
	}
	// ...then flood BAD-SIGNATURE events for "ghost". If a rejected message moved
	// the baseline, "ghost" would become an outlier; it must not.
	ghost, _ := identity.Generate("nobody")
	for i := 0; i < 50; i++ {
		payload, _ := proto.Marshal(eventFor("e", "ghost"))
		env := &corev1.SignedTelemetry{AgentId: "nobody", Sequence: uint64(i + 1), Kind: "event",
			Payload: payload, Signature: ghost.Sign(uint64(i+1), payload)}
		b, _ := proto.Marshal(env)
		_ = conn.Publish(natsx.SubjectSigned, b)
	}

	waitFor(t, func() bool { return srv.RejectedTelemetry.Load() >= 50 })
	// Give any (erroneous) alert path a moment to fire.
	time.Sleep(150 * time.Millisecond)
	if got := srv.PeerAlerts.Load(); got != 0 {
		t.Errorf("peer alerts = %d from UNVERIFIED telemetry — a rejected message moved the baseline", got)
	}
	if got := peerAlertCount(t, "ghost"); got != 0 {
		t.Errorf("the rejected 'ghost' subject raised %d peer alerts", got)
	}
}

// The default control plane (peer-UEBA NOT enabled) observes no subject and records
// no peer alert, even fed a blatant outlier — off by default is the D23 gate.
func TestPeerDisabledByDefault(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url) // plain New — peer-UEBA never enabled
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-off")
	ctx := context.Background()

	for _, s := range []string{"p1", "p2"} {
		_ = pub.PublishEvent(ctx, eventFor("e", s))
	}
	for i := 0; i < 40; i++ {
		_ = pub.PublishEvent(ctx, eventFor("e", "outlier"))
	}
	// Wait until the telemetry is definitely processed (last event stored)...
	waitFor(t, func() bool {
		rows, _ := srv.Telemetry(ctx, "agent-off")
		return len(rows) >= 42
	})
	if got := srv.PeerAlerts.Load(); got != 0 {
		t.Errorf("disabled server recorded %d peer alerts — off-by-default (D23) violated", got)
	}
	if got := peerAlertCount(t, "outlier"); got != 0 {
		t.Errorf("disabled server wrote %d peer_alerts rows for the outlier", got)
	}
}

// Many above-threshold events from one outlier yield ONE alert within the cooldown,
// not one per event — the rising-edge limiter throttles the alert, not the signal.
func TestPeerAlertCooldown(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServerPeer(t, url, 0.5, time.Hour)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-cd")
	ctx := context.Background()

	for _, s := range []string{"p1", "p2", "p3"} {
		for i := 0; i < 3; i++ {
			_ = pub.PublishEvent(ctx, eventFor("e", s))
		}
	}
	// The outlier crosses the threshold and then keeps going — each subsequent
	// event is still above threshold but must NOT re-alert within the cooldown.
	for i := 0; i < 60; i++ {
		_ = pub.PublishEvent(ctx, eventFor("e", "outlier"))
	}

	waitFor(t, func() bool { return srv.PeerAlerts.Load() >= 1 })
	// Let all 60 be processed so any missing throttle would show as extra alerts.
	waitFor(t, func() bool {
		rows, _ := srv.Telemetry(ctx, "agent-cd")
		return len(rows) >= 69
	})
	time.Sleep(100 * time.Millisecond)
	if got := peerAlertCount(t, "outlier"); got != 1 {
		t.Errorf("peer alerts for outlier = %d, want 1 — the cooldown did not throttle repeat alerts", got)
	}
}
