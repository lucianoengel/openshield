package beacon_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/analytics/beacon"
)

// NIPS-6: beaconing detection. The tests are as much about what it must NOT fire on as what it must.

func series(dest string, start time.Time, every time.Duration, n int, jitter func(int) time.Duration) []beacon.Contact {
	out := make([]beacon.Contact, 0, n)
	at := start
	for i := 0; i < n; i++ {
		j := time.Duration(0)
		if jitter != nil {
			j = jitter(i)
		}
		out = append(out, beacon.Contact{At: at.Add(j), Destination: dest})
		at = at.Add(every)
	}
	return out
}

func TestAMetronomeIsDetected(t *testing.T) {
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	got := beacon.Detect(series("c2.evil.example", start, 60*time.Second, 20, nil), beacon.DefaultOptions())
	if len(got) != 1 {
		t.Fatalf("found %d beacons %+v, want 1", len(got), got)
	}
	f := got[0]
	if f.Destination != "c2.evil.example" || f.Contacts != 20 {
		t.Errorf("finding = %+v", f)
	}
	if f.Interval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", f.Interval)
	}
	if f.Regularity < 0.99 {
		t.Errorf("regularity = %v, want ~1.0 for a perfect metronome", f.Regularity)
	}
	// The evidence must be present: a finding an analyst cannot dismiss quickly is one they will
	// eventually ignore entirely, and this detector's base rate makes that fatal.
	if f.First.IsZero() || f.Last.IsZero() || f.Last.Before(f.First) {
		t.Errorf("finding carries no usable time range: %+v", f)
	}
}

// TestJitteredBeaconsAreStillDetected — every real C2 framework configures jitter, so a detector that only
// catches metronomes catches only the misconfigured.
//
// Mutation: use the standard deviation instead of the median absolute deviation → a single long gap
// inflates it and this FAILS.
func TestJitteredBeaconsAreStillDetected(t *testing.T) {
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	r := rand.New(rand.NewSource(7))
	// 60s ± up to 5s — roughly an 8% jitter, a common default.
	contacts := series("c2.evil.example", start, 60*time.Second, 24, func(int) time.Duration {
		return time.Duration(r.Intn(5000)) * time.Millisecond
	})
	// AND one long outage: a laptop that slept, a link that dropped. It must not hide the beacon.
	contacts = append(contacts, beacon.Contact{
		At: start.Add(40 * time.Minute), Destination: "c2.evil.example"})

	got := beacon.Detect(contacts, beacon.DefaultOptions())
	if len(got) != 1 {
		t.Fatalf("a jittered beacon with one outage was not detected (%+v) — hiding by dropping a single "+
			"check-in should not be that easy", got)
	}
	if got[0].Jitter <= 0 {
		t.Error("jitter was reported as zero for a jittered series")
	}
}

// TestWhatItMustNotFireOn is the half that decides whether this detector survives contact with a real
// network.
func TestWhatItMustNotFireOn(t *testing.T) {
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	o := beacon.DefaultOptions()

	t.Run("too few contacts", func(t *testing.T) {
		// Three contacts give two intervals, and two intervals are always "regular". Calling that a
		// beacon would make the detector fire on almost any pair of repeated connections.
		if got := beacon.Detect(series("x.example", start, time.Minute, 3, nil), o); len(got) != 0 {
			t.Errorf("fired on %d contacts: %+v", 3, got)
		}
	})
	t.Run("irregular human browsing", func(t *testing.T) {
		r := rand.New(rand.NewSource(11))
		var contacts []beacon.Contact
		at := start
		for i := 0; i < 30; i++ {
			at = at.Add(time.Duration(5+r.Intn(600)) * time.Second)
			contacts = append(contacts, beacon.Contact{At: at, Destination: "news.example"})
		}
		if got := beacon.Detect(contacts, o); len(got) != 0 {
			t.Errorf("fired on irregular traffic: %+v", got)
		}
	})
	t.Run("a burst is not a rhythm", func(t *testing.T) {
		// Connections milliseconds apart are a transfer or a retry storm, not a check-in.
		if got := beacon.Detect(series("cdn.example", start, 50*time.Millisecond, 40, nil), o); len(got) != 0 {
			t.Errorf("fired on a burst: %+v", got)
		}
	})
	t.Run("allowlisted destinations", func(t *testing.T) {
		// A detector whose output is mostly known-good gets muted, and a muted detector is worse than
		// none — so the allowlist is an input, not an afterthought.
		o2 := o
		o2.Allowlist = map[string]bool{"ntp.pool.example": true}
		if got := beacon.Detect(series("ntp.pool.example", start, time.Hour, 24, nil), o2); len(got) != 0 {
			t.Errorf("fired on an allowlisted destination: %+v", got)
		}
		// ...and still fires on everything else.
		if got := beacon.Detect(series("c2.example", start, time.Hour, 24, nil), o2); len(got) != 1 {
			t.Errorf("the allowlist suppressed an unrelated destination: %+v", got)
		}
	})
}

// TestDetectDoesNotMutateItsInput — sorting a caller's data as a side effect of measuring it is the kind
// of surprise that surfaces as a bug somewhere else entirely.
func TestDetectDoesNotMutateItsInput(t *testing.T) {
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	contacts := series("c2.example", start, time.Minute, 12, nil)
	// Shuffle so any in-place sort would be observable.
	contacts[0], contacts[11] = contacts[11], contacts[0]
	first := contacts[0].At
	beacon.Detect(contacts, beacon.DefaultOptions())
	if !contacts[0].At.Equal(first) {
		t.Error("Detect reordered its caller's slice")
	}
}

// TestFindingsAreRankedMostRegularFirst: the order an analyst reads top-down should be the order the
// detector is most confident about.
func TestFindingsAreRankedMostRegularFirst(t *testing.T) {
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	r := rand.New(rand.NewSource(3))
	var contacts []beacon.Contact
	contacts = append(contacts, series("perfect.example", start, time.Minute, 20, nil)...)
	contacts = append(contacts, series("noisy.example", start, time.Minute, 20, func(int) time.Duration {
		return time.Duration(r.Intn(9000)) * time.Millisecond
	})...)
	got := beacon.Detect(contacts, beacon.DefaultOptions())
	if len(got) != 2 {
		t.Fatalf("found %d, want 2: %+v", len(got), got)
	}
	if got[0].Destination != "perfect.example" {
		t.Errorf("ranking put %q first; the most regular should lead", got[0].Destination)
	}
}
