//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// BEACONING DETECTION over real telemetry (D319).
//
// NIPS-6 looks for the rhythm that command-and-control traffic has and human browsing does not: the same
// destination, contacted at a regular interval, for long enough that regularity is not coincidence. Five
// settings tune it — the sweep interval, the rhythm window, the minimum contacts, the minimum regularity
// and an allowlist — and none was exercised against a running control plane.
//
// THE DETECTOR ONLY SEES VERIFIED TELEMETRY (D44), which is what makes this worth an integration test
// rather than a package one. `beacon.Analyze` can be given a slice of contacts in a unit test; what that
// cannot show is that the sweep reads from the right place, honours the verified filter, and produces an
// alert an operator can find. A forger who could steer this would be able to manufacture a
// command-and-control finding against any host they chose.
//
// AND THE ALLOWLIST IS THE HALF THAT DECIDES WHETHER ANYONE KEEPS IT ON. Most beacons on a real network
// are legitimate — telemetry agents, update checkers, monitoring probes — so a sweep without a way to
// silence the known ones produces a page of findings every morning and gets muted, taking the real
// detection with it.

// enrolledPublisher enrols an identity with the control plane and returns a publisher whose telemetry
// the server will VERIFY.
//
// It exists because the fleet agent publishes its own synthetic events on its own schedule, which is the
// wrong instrument for a detector about TIMING: a rhythm has to be dictated by the test, not observed
// from whatever the agent happened to do.
func enrolledPublisher(t *testing.T, stack *Stack, enrollURL, agentID string) *natsx.SignedPublisher {
	t.Helper()
	id, _, err := identity.LoadOrCreate("", agentID)
	if err != nil {
		t.Fatalf("creating an identity: %v", err)
	}
	token := issueToken(t, stack, agentID)
	if err := enrollpkg.Enroll(Ctx(t), http.DefaultClient, enrollURL, agentID, token, id); err != nil {
		t.Fatalf("enrolling %s: %v", agentID, err)
	}
	conn, err := nats.Connect(stack.NATSURL)
	if err != nil {
		t.Fatalf("connecting to the broker: %v", err)
	}
	t.Cleanup(conn.Close)
	return natsx.NewSignedPublisher(agentID, id, conn)
}

// publishRhythm sends `count` NETWORK_FLOW events to one destination, evenly spaced in the PAST.
//
// The timestamps are backdated rather than produced in real time, because a test that actually waited out
// a rhythm would take as long as the rhythm — and the detector measures the EVENT's observation time
// precisely so that a rhythm is a property of the endpoint rather than of when telemetry happened to
// arrive.
func publishRhythm(t *testing.T, pub *natsx.SignedPublisher, subject, dest string, count int, every time.Duration) {
	t.Helper()
	start := time.Now().Add(-time.Duration(count) * every)
	for i := 0; i < count; i++ {
		ev := &corev1.Event{
			EventId:     fmt.Sprintf("beacon-%s-%d", dest, i),
			AgentId:     "agent-beacon",
			ConnectorId: "integration",
			Kind:        corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
			ObservedAt:  timestamppb.New(start.Add(time.Duration(i) * every)),
			Subject:     &corev1.Subject{PseudonymousId: subject},
			Target:      &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: dest}},
		}
		if err := pub.PublishEvent(Ctx(t), ev); err != nil {
			t.Fatalf("publishing a flow to %s: %v", dest, err)
		}
	}
}

// beaconAlerts counts findings for a destination.
//
// IT MATCHES ON THE DEDUP KEY, not the title, and that is a deliberate consequence of the design rather
// than a convenience. D241 keeps the alert TITLE a closed-vocabulary label — "network beaconing" — so
// that an observable never appears in an alert list; the destination lives in the detector-namespaced
// dedup key `beacon:<subject>:<destination>:<interval>s`. A test asserting on the title could not tell
// two beacons apart, which is the whole question here.
func beaconAlerts(t *testing.T, stack *Stack, dest string) int {
	t.Helper()
	pool := openPool(t, stack.DSN)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM unified_alerts WHERE domain='nips' AND dedup_key LIKE 'beacon:%:' || $1 || ':%'`,
		dest).Scan(&n); err != nil {
		t.Fatalf("counting beaconing findings: %v", err)
	}
	return n
}

func startBeaconServer(t *testing.T, stack *Stack, allowlist string) (*Process, string) {
	t.Helper()
	migrateStack(t, stack)
	setDynamic(t, stack, "OPENSHIELD_BEACON_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_BEACON_WINDOW", "24h")
	setDynamic(t, stack, "OPENSHIELD_BEACON_MIN_CONTACTS", "8")
	setDynamic(t, stack, "OPENSHIELD_BEACON_MIN_REGULARITY", "0.8")
	if allowlist != "" {
		setDynamic(t, stack, "OPENSHIELD_BEACON_ALLOWLIST", allowlist)
	}
	srv, enrollURL := startServer(t, stack)
	srv.WaitForOutput("beaconing sweep loop ACTIVE", 90*time.Second)
	return srv, enrollURL
}

// TestARegularBeaconIsFoundAndIrregularTrafficIsNot is the pair, together, because a detector that fired
// on everything would satisfy the positive alone — and on a real network that detector gets muted within
// a week, taking the genuine findings with it.
func TestARegularBeaconIsFoundAndIrregularTrafficIsNot(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startBeaconServer(t, stack, "")
	pub := enrolledPublisher(t, stack, enrollURL, "agent-beacon")

	const beaconing = "c2.evil.example"
	const browsing = "news.example"

	// A METRONOME: same destination, evenly spaced.
	publishRhythm(t, pub, "subject-beacon", beaconing, 20, 30*time.Second)

	// AND HUMAN-SHAPED TRAFFIC to another destination: the SAME NUMBER of contacts over a comparable
	// span, with genuinely irregular gaps. Equal volume is the point — a detector keying on "many
	// contacts" rather than on rhythm would flag both, and this is what tells them apart.
	//
	// THE GAPS ARE ALL DIFFERENT AND WIDELY SPREAD, which the first version got wrong: it used a
	// repeating 27s/27s/6s pattern, and regularity is 1 - MAD/median where MAD is the MEDIAN absolute
	// deviation. Two-thirds of those gaps were identical, so the MAD was ZERO and the score a perfect
	// 1.0. Robustness to outliers is exactly what a beacon detector wants — an implant that misses a
	// check-in is still an implant — and it means "irregular" has to mean irregular THROUGHOUT, not
	// mostly-regular with interruptions.
	gaps := []int{15, 420, 60, 900, 25, 300, 120, 1500, 35, 700, 90, 1100, 45, 250, 180, 800, 30, 600, 70}
	at := time.Now().Add(-6 * time.Hour)
	for i := 0; i <= len(gaps); i++ {
		ev := &corev1.Event{
			EventId:     fmt.Sprintf("browse-%d", i),
			AgentId:     "agent-beacon",
			ConnectorId: "integration",
			Kind:        corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
			ObservedAt:  timestamppb.New(at),
			Subject:     &corev1.Subject{PseudonymousId: "subject-beacon"},
			Target:      &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: browsing}},
		}
		if err := pub.PublishEvent(Ctx(t), ev); err != nil {
			t.Fatal(err)
		}
		if i < len(gaps) {
			at = at.Add(time.Duration(gaps[i]) * time.Second)
		}
	}

	Eventually(t, 120*time.Second, "a beaconing finding for the metronome", func() bool {
		return beaconAlerts(t, stack, beaconing) > 0
	})
	if n := beaconAlerts(t, stack, browsing); n != 0 {
		t.Errorf("%d finding(s) for BURSTY traffic to %s. The whole claim is that rhythm distinguishes "+
			"command-and-control from browsing; a detector that also fires on irregular traffic of the "+
			"same volume is counting contacts, and on a real network it gets muted within a week", n, browsing)
	}
}

// TestAnAllowlistedDestinationIsNotReported.
//
// Most beacons on a real network are legitimate. The allowlist is what lets an operator keep the sweep
// ON, and a sweep that cannot be quietened about a known telemetry endpoint is one that gets turned off.
func TestAnAllowlistedDestinationIsNotReported(t *testing.T) {
	stack := StartStack(t)
	const known = "telemetry.vendor.example"
	const unknown = "c2.other.example"
	_, enrollURL := startBeaconServer(t, stack, known)
	pub := enrolledPublisher(t, stack, enrollURL, "agent-allowlist")

	// IDENTICAL rhythms to both destinations, so the ONLY difference is the allowlist. Publishing only
	// the allowlisted one would leave "no findings" satisfiable by a sweep that never ran.
	publishRhythm(t, pub, "subject-allow", known, 20, 30*time.Second)
	publishRhythm(t, pub, "subject-allow", unknown, 20, 30*time.Second)

	Eventually(t, 120*time.Second, "a finding for the destination that is NOT allowlisted", func() bool {
		return beaconAlerts(t, stack, unknown) > 0
	})
	if n := beaconAlerts(t, stack, known); n != 0 {
		t.Errorf("%d finding(s) for the ALLOWLISTED destination %s, whose rhythm is identical to the one "+
			"that was correctly reported", n, known)
	}
}

// TestUnverifiedTelemetryCannotManufactureABeacon is D44 at the analytics layer.
//
// Unverified telemetry is not evidence. If it steered this detector, anyone able to reach the broker
// could manufacture a command-and-control finding against any host they named — turning a detection
// capability into a way to direct an investigation at a chosen person.
func TestUnverifiedTelemetryCannotManufactureABeacon(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startBeaconServer(t, stack, "")
	const forged = "framed.example"
	const genuine = "real-c2.example"

	// UNSIGNED: no envelope, no identity, no enrollment — what anything that can reach the broker can do.
	tr, err := natsx.Connect(stack.NATSURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	start := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 20; i++ {
		ev := &corev1.Event{
			EventId:     fmt.Sprintf("forged-beacon-%d", i),
			AgentId:     "agent-not-enrolled",
			ConnectorId: "integration",
			Kind:        corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
			ObservedAt:  timestamppb.New(start.Add(time.Duration(i) * 30 * time.Second)),
			Subject:     &corev1.Subject{PseudonymousId: "subject-framed"},
			Target:      &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: forged}},
		}
		if err := tr.PublishEvent(Ctx(t), ev); err != nil {
			t.Fatal(err)
		}
	}

	// A GENUINE beacon alongside, so "no finding for the forged one" cannot be satisfied by a sweep that
	// is simply not running. This is the control that makes the negative mean something.
	pub := enrolledPublisher(t, stack, enrollURL, "agent-genuine")
	publishRhythm(t, pub, "subject-genuine", genuine, 20, 30*time.Second)

	Eventually(t, 120*time.Second, "a finding from VERIFIED telemetry", func() bool {
		return beaconAlerts(t, stack, genuine) > 0
	})
	if n := beaconAlerts(t, stack, forged); n != 0 {
		t.Errorf("%d finding(s) built from UNVERIFIED telemetry naming %s. Anyone able to reach the "+
			"broker could then manufacture a command-and-control finding against a host of their "+
			"choosing, which turns a detector into a way to point an investigation at a person", n, forged)
	}
}
