package controlplane_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// NIPS-6: beaconing over the fleet aggregate.

func seedFlow(t *testing.T, srv *controlplane.Server, subject, dest string, at time.Time, verified bool) {
	t.Helper()
	ev := &corev1.Event{
		EventId: subject + dest + at.Format(time.RFC3339Nano), AgentId: "agent-nips6",
		Kind: corev1.EventKind_EVENT_KIND_NETWORK_FLOW, ObservedAt: timestamppb.New(at),
		Subject: &corev1.Subject{PseudonymousId: subject},
		Target:  &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: dest}},
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	srv.InsertFleetTelemetryForTest(t, "agent-nips6", ev.EventId, payload, verified)
}

// TestBeaconIsDetectedFromVerifiedFlows, and the alert carries no observable in its title (D241).
//
// Mutation: pool contacts across subjects instead of grouping per subject → a rhythm nobody exhibits is
// synthesized → FAILS.
func TestBeaconIsDetectedFromVerifiedFlows(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// One endpoint checking in every 60s.
	for i := 0; i < 20; i++ {
		seedFlow(t, srv, "subject-beacon", "c2.evil.example", now.Add(-time.Duration(20-i)*time.Minute), true)
	}
	// And irregular browsing that must not fire.
	for i, d := range []time.Duration{1, 7, 3, 44, 9, 21, 2, 33, 5, 17} {
		seedFlow(t, srv, "subject-beacon", "news.example", now.Add(-time.Duration(i*60+int(d))*time.Second), true)
	}

	n, err := srv.DetectBeaconing(ctx, controlplane.BeaconRule{Window: 2 * time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recorded %d beacon alert(s), want 1 — irregular traffic must not fire", n)
	}
	var found bool
	var severity, title string
	if err := pool.QueryRow(ctx,
		`SELECT severity, title FROM unified_alerts WHERE domain='nips' LIMIT 1`).Scan(&severity, &title); err == nil {
		found = true
		a := struct{ Severity, Title string }{severity, title}
		if a.Severity != controlplane.SeverityMedium {
			t.Errorf("severity = %q, want medium — on a real network most beacons are legitimate, and a "+
				"detector that cries critical at NTP is muted within a week", a.Severity)
		}
		// D241: the title is a closed-vocabulary label. Putting the destination there would place an
		// observable in every alert list that renders a title.
		if a.Title != "network beaconing" {
			t.Errorf("title = %q, want the closed label", a.Title)
		}
		if containsStr(a.Title, "evil.example") {
			t.Error("the alert title leaks the destination")
		}
	}
	if !found {
		t.Error("no nips alert recorded")
	}

	// A second sweep must not re-alert: the same beacon re-detected is the same finding.
	if n2, err := srv.DetectBeaconing(ctx, controlplane.BeaconRule{Window: 2 * time.Hour}, now); err != nil {
		t.Fatal(err)
	} else if n2 != 1 {
		t.Errorf("the second sweep recorded %d, want 1 detection", n2)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM unified_alerts WHERE domain='nips'`); got != 1 {
		t.Errorf("%d alert rows after two sweeps, want 1 — a re-detected beacon must not re-alert", got)
	}
}

// TestUnverifiedFlowsCannotManufactureABeacon (D44). Beaconing is derived purely from timing, so unsigned
// telemetry could otherwise fabricate a beacon against any destination.
//
// Mutation: drop `AND verified` → FAILS.
func TestUnverifiedFlowsCannotManufactureABeacon(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 20; i++ {
		seedFlow(t, srv, "subject-forged", "victim.example", now.Add(-time.Duration(20-i)*time.Minute), false)
	}
	n, err := srv.DetectBeaconing(ctx, controlplane.BeaconRule{Window: 2 * time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("unverified telemetry produced %d beacon alert(s) — anyone able to publish unsigned "+
			"telemetry could then manufacture a beacon against a destination of their choosing", n)
	}
}

// TestAllowlistedDestinationsAreNotAlerted — the allowlist is configuration because a detector whose
// output is mostly known-good gets muted.
func TestAllowlistedDestinationsAreNotAlerted(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 20; i++ {
		seedFlow(t, srv, "subject-allow", "ntp.pool.example", now.Add(-time.Duration(20-i)*time.Minute), true)
	}
	n, err := srv.DetectBeaconing(ctx, controlplane.BeaconRule{
		Window: 2 * time.Hour, Allowlist: []string{"ntp.pool.example"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("an allowlisted destination produced %d alert(s)", n)
	}
}

func containsStr(h, n string) bool {
	return len(h) >= len(n) && (func() bool {
		for i := 0; i+len(n) <= len(h); i++ {
			if h[i:i+len(n)] == n {
				return true
			}
		}
		return false
	})()
}

// TestAFleetIsNotABeacon backs a claim the code makes and my first test set did NOT check: contacts are
// grouped PER SUBJECT, because a rhythm is a property of one endpoint talking to one destination.
//
// The fixture is the realistic version of getting this wrong: ten hosts each checking for updates hourly
// at staggered offsets. No single host has enough contacts to be a beacon, but POOLED they form a dense,
// highly regular stream — a rhythm nobody actually exhibits.
//
// Mutation: pool contacts across subjects → the fleet's update check is reported as a beacon → FAILS.
func TestAFleetIsNotABeacon(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// 10 hosts x 3 check-ins each: 30 contacts pooled, but only 3 per host.
	for host := 0; host < 10; host++ {
		offset := time.Duration(host*6) * time.Minute // staggered, as real fleets are
		for i := 0; i < 3; i++ {
			at := now.Add(-3*time.Hour + offset + time.Duration(i)*time.Hour)
			seedFlow(t, srv, fmt.Sprintf("subject-fleet-%d", host), "updates.example", at, true)
		}
	}

	n, err := srv.DetectBeaconing(ctx, controlplane.BeaconRule{Window: 6 * time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a fleet's staggered update check produced %d beacon alert(s) — pooling contacts across "+
			"subjects synthesizes a rhythm no endpoint exhibits, and on a real network that is most of "+
			"the traffic", n)
	}
}
