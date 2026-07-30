package controlplane_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// CLOCK SKEW, the third of the four properties the enterprise gap assessment named as unproven.
//
// The finding it produced is worth stating precisely, because it is neither "all fine" nor "all broken":
// liveness was ALREADY immune (the dead-man's-switch reads the control plane's own receipt time, SEC-3),
// and beaconing detection was NOT — it reads the endpoint's reported observation time, which on a
// compromised host is written by the implant whose rhythm is being measured.

func TestTheDefaultSkewToleranceIsLooseEnoughForARealFleet(t *testing.T) {
	// A tolerance of seconds would put every virtual machine resuming from suspend into a permanent alert,
	// and a permanent alert is one nobody reads. This is a plausibility bound, not a synchronisation
	// requirement — so the test pins the ORDER OF MAGNITUDE, not the exact value.
	got := controlplane.SkewTolerance()
	if got < 30*time.Second {
		t.Errorf("skew tolerance %s is tight enough that ordinary clock drift would alert continuously", got)
	}
	if got > 15*time.Minute {
		t.Errorf("skew tolerance %s is loose enough to be no check at all", got)
	}
}

func TestTheToleranceIsConfigurableAndARubbishValueDoesNotDisableIt(t *testing.T) {
	t.Setenv("OPENSHIELD_CLOCK_SKEW_TOLERANCE", "30s")
	if got := controlplane.SkewTolerance(); got != 30*time.Second {
		t.Errorf("configured tolerance = %s, want 30s", got)
	}
	// A TYPO MUST NOT DISABLE THE CHECK. Falling back to the default is the safe direction; parsing "" or
	// "-1h" as "no bound" would silently trust every clock, which is the failure this exists to prevent.
	for _, bad := range []string{"nonsense", "-1h", "0"} {
		t.Setenv("OPENSHIELD_CLOCK_SKEW_TOLERANCE", bad)
		if got := controlplane.SkewTolerance(); got != controlplane.DefaultSkewTolerance {
			t.Errorf("tolerance %q gave %s, want the default — a malformed bound must not become no bound",
				bad, got)
		}
	}
}

// TestOnlyAFutureTimestampIsTreatedAsImplausible is the decision this change makes, asserted directly.
//
// The end-to-end version — "a future-dated beacon is still detected" — CANNOT WORK, and finding out why was
// the useful part. Seeding flows inserts them in a tight loop, so their receipt times are milliseconds
// apart and the fallback has no rhythm to find. The first version of that test passed anyway, on rows a
// previous test had left in a shared table; clearing before seeding exposed it. A test that passes on
// another test's leftovers is worse than no test.
//
// So the decision is tested where it is made, and the existing beaconing cases are what prove the normal
// path still works.
func TestOnlyAFutureTimestampIsTreatedAsImplausible(t *testing.T) {
	received := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	const tolerance = 2 * time.Minute
	ev := func(observed time.Time) *corev1.Event {
		return &corev1.Event{ObservedAt: timestamppb.New(observed)}
	}

	// TRUSTED: at receipt, slightly ahead within tolerance, and far in the PAST.
	//
	// The past case is the load-bearing one. Every event this product spools while an agent is offline
	// (D40/D67) arrives dated hours earlier, so treating the past as suspicious destroys beaconing
	// detection outright — measured, it took detections from 1 to 0.
	for _, observed := range []time.Time{
		received,
		received.Add(time.Minute),
		received.Add(-6 * time.Hour),
		received.Add(-30 * 24 * time.Hour),
	} {
		when, trusted := controlplane.PlausibleObservationTimeForTest(ev(observed), received, tolerance)
		if !trusted {
			t.Errorf("observed %s (receipt %s) was distrusted — a timestamp in the past is what every spooled "+
				"event legitimately has", observed, received)
		}
		if !when.Equal(observed) {
			t.Errorf("trusted event used %s, want its own %s", when, observed)
		}
	}

	// DISTRUSTED: beyond tolerance in the FUTURE. An event cannot be observed after it was received, so
	// there is no benign reading, and it falls back to receipt time.
	before := controlplane.SkewedEvents()
	when, trusted := controlplane.PlausibleObservationTimeForTest(ev(received.Add(7*24*time.Hour)), received, tolerance)
	if trusted {
		t.Fatal("a timestamp a week in the FUTURE was trusted. It cannot be true, and trusting it lets an " +
			"endpoint place its own traffic outside the window meant to catch it")
	}
	if !when.Equal(received) {
		t.Errorf("an implausible event used %s, want the receipt time %s", when, received)
	}
	if controlplane.SkewedEvents() <= before {
		t.Error("the fallback was not counted — a fleet running on receipt time must not look identical to " +
			"one running on observation time")
	}

	// MISSING is not lying. An absent timestamp falls back too, and must NOT be counted as skew, or the
	// signal drowns in events that simply had no time on them.
	before = controlplane.SkewedEvents()
	if _, trusted := controlplane.PlausibleObservationTimeForTest(&corev1.Event{}, received, tolerance); trusted {
		t.Error("an event with no timestamp was trusted")
	}
	if controlplane.SkewedEvents() != before {
		t.Error("a missing timestamp was counted as clock skew — missing data and a lying clock are " +
			"different findings and conflating them buries the one that matters")
	}
}
