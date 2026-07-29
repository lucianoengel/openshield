package prefilter

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// THE CYCLE BREAKER (B2 tier 2).
//
// These are cheap tests of an expensive property. The failure this guards against does not present as
// a red test — the async classification opens the file, that open is gated, and answering it submits
// again — it presents as a host wedged in an uninterruptible permission window. So the behaviour is
// pinned here, where it can be exercised in microseconds, and the VM test only has to show that the
// same logic terminates against a real kernel.

// fakeClock drives the suppressor's time so expiry is asserted rather than slept for.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestSuppressor builds a suppressor on a fake clock.
func newTestSuppressor(t *testing.T, ttl, hold time.Duration, max int) (*PathSuppressor, *fakeClock) {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)}
	s := NewPathSuppressor(ttl, hold, max)
	s.now = c.now
	return s, c
}

// TestOnePathSubmitsOnceWhileItsClassificationRuns is the cycle breaker itself: the second question
// about a path — which in production is the classifier's OWN open of it — must not submit again.
func TestOnePathSubmitsOnceWhileItsClassificationRuns(t *testing.T) {
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, 16)

	if !s.Admit("/watched/report.csv") {
		t.Fatal("the first submission for a path was declined — no gated open would ever be fully classified")
	}
	if s.Admit("/watched/report.csv") {
		t.Fatal("a second submission for the same path was admitted. In production that second question " +
			"IS the classifier's own open, so this submits again, which opens again — an unbounded loop " +
			"whose failure mode is a host wedged in an uninterruptible permission window, not a red test")
	}
	if got := s.Suppressed(); got != 1 {
		t.Errorf("Suppressed() = %d, want 1 — a decline that is not counted is a decision nobody can see", got)
	}
}

// TestADifferentPathIsStillSubmitted: without this, "submit once" is satisfied by a suppressor that
// declines everything after the first file, and every other gated open would go unclassified.
func TestADifferentPathIsStillSubmitted(t *testing.T) {
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, 16)
	if !s.Admit("/watched/a.csv") {
		t.Fatal("the first path was declined")
	}
	if !s.Admit("/watched/b.csv") {
		t.Fatal("a DIFFERENT path was declined while the first was in flight — suppression is keyed on " +
			"something other than the path, so one file in flight blinds the gate to every other")
	}
}

// TestAPendingEntryDoesNotExpire is the property a plain TTL does not have, and the reason Done exists.
//
// If the entry expired while its classification was still queued, the classification's open would
// arrive after expiry, submit again, and the cycle would restart every TTL — forever, and more slowly
// each time, which is the hardest kind of loop to notice.
func TestAPendingEntryDoesNotExpire(t *testing.T) {
	const ttl = time.Minute
	s, clock := newTestSuppressor(t, ttl, time.Hour, 16)

	if !s.Admit("/watched/slow.csv") {
		t.Fatal("the first submission was declined")
	}
	// Far past the TTL, but the classification has not reported.
	clock.advance(50 * ttl)
	if s.Admit("/watched/slow.csv") {
		t.Fatal("a path whose classification is still PENDING was admitted again after the TTL. The " +
			"suppression must cover the gap between submitting and the open that submission causes, " +
			"however long the queue is — otherwise a slow queue restarts the cycle every TTL")
	}
}

// TestTheTtlRunsFromDoneAndThenExpires: the suppression is not permanent. A file opened again well
// after its classification finished is classified again.
func TestTheTtlRunsFromDoneAndThenExpires(t *testing.T) {
	const ttl = time.Minute
	s, clock := newTestSuppressor(t, ttl, time.Hour, 16)

	if !s.Admit("/watched/x.csv") {
		t.Fatal("the first submission was declined")
	}
	clock.advance(10 * time.Second) // the classification runs
	s.Done("/watched/x.csv")

	clock.advance(ttl / 2)
	if s.Admit("/watched/x.csv") {
		t.Error("the path was re-submitted INSIDE the TTL — a burst of opens of one unchanged file would " +
			"each cost a full-file classification")
	}
	clock.advance(ttl)
	if !s.Admit("/watched/x.csv") {
		t.Error("the path was never re-submitted after the TTL elapsed. Suppression that never lifts is " +
			"a file classified once for the life of the process, whatever is written to it afterwards")
	}
}

// TestReleaseForgetsAnUnclassifiedSubmission. Release is for a submission that was admitted and never
// ran — a full queue. Forgetting is correct precisely because nothing was classified: no classification
// means no open of our own, so there is no cycle to re-arm, and the next open SHOULD try again.
func TestReleaseForgetsAnUnclassifiedSubmission(t *testing.T) {
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, 16)
	if !s.Admit("/watched/dropped.csv") {
		t.Fatal("the first submission was declined")
	}
	s.Release("/watched/dropped.csv")
	if !s.Admit("/watched/dropped.csv") {
		t.Error("a released path stayed suppressed. The submission never ran, so the file was gated and " +
			"never fully classified, and the retry that would fix that is being refused")
	}
}

// TestAPendingEntryIsReleasedByTheHold: a classification that dies without reporting must not suppress
// its path for the life of the process.
func TestAPendingEntryIsReleasedByTheHold(t *testing.T) {
	const hold = 5 * time.Minute
	s, clock := newTestSuppressor(t, time.Minute, hold, 16)

	if !s.Admit("/watched/crashed.csv") {
		t.Fatal("the first submission was declined")
	}
	clock.advance(hold + time.Second)
	if !s.Admit("/watched/crashed.csv") {
		t.Fatal("a pending entry whose classification never reported suppressed its path past the hold. " +
			"A worker that dies mid-classification would blind the gate to that file permanently")
	}
	if got := s.Abandoned(); got != 1 {
		t.Errorf("Abandoned() = %d, want 1 — work was submitted and its completion lost, which is exactly "+
			"the kind of gap that must not be inferred from silence", got)
	}
}

// TestTheCacheDoesNotGrowWithoutBound. The keys are paths, so they are whatever the host opens — an
// unbounded map here is a memory primitive in the process the gate depends on staying up.
func TestTheCacheDoesNotGrowWithoutBound(t *testing.T) {
	const max = 32
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, max)

	for i := 0; i < max*10; i++ {
		s.Admit("/watched/f" + strconv.Itoa(i))
	}
	if n := s.Len(); n > max {
		t.Errorf("the suppression cache holds %d entries with a ceiling of %d — paths are "+
			"attacker-influenced, so a map that grows with them is a memory primitive", n, max)
	}
	if s.Saturated() == 0 {
		t.Error("the ceiling was reached and nothing was counted. Declined submissions mean files were " +
			"gated and never fully classified; a detection gap that is not counted reads as a quiet estate")
	}
}

// TestAFullCacheDeclinesRatherThanEvictingALiveEntry.
//
// The direction of this failure is the whole point. Evicting a live entry to make room would re-arm
// the cycle for the evicted path — the loop this type exists to break. Declining costs a missed
// asynchronous classification, which is a counted detection gap. Given the choice, take the gap.
func TestAFullCacheDeclinesRatherThanEvictingALiveEntry(t *testing.T) {
	const max = 4
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, max)

	for i := 0; i < max; i++ {
		if !s.Admit("/watched/live" + strconv.Itoa(i)) {
			t.Fatalf("path %d was declined below the ceiling", i)
		}
	}
	if s.Admit("/watched/overflow") {
		t.Fatal("a new path was admitted into a full cache")
	}
	// The entry admitted FIRST must still suppress: if it had been evicted, its classification's own
	// open would submit again, and the cycle is back.
	if s.Admit("/watched/live0") {
		t.Fatal("a live, still-pending entry was evicted to make room. That path's classification is " +
			"running right now, so its own open would be admitted again — the loop, restored by the " +
			"very mechanism meant to bound memory")
	}
}

// TestAdmitIsSafeUnderConcurrency: it is called from the gate's handler goroutines, one per blocked
// process, so exactly one of N racing submissions for the same path must win.
func TestAdmitIsSafeUnderConcurrency(t *testing.T) {
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, 64)

	const racers = 32
	var wg sync.WaitGroup
	admitted := make(chan struct{}, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Admit("/watched/contended.csv") {
				admitted <- struct{}{}
			}
		}()
	}
	wg.Wait()
	if n := len(admitted); n != 1 {
		t.Errorf("%d of %d concurrent submissions for one path were admitted, want exactly 1. Each "+
			"admitted submission is a full-file classification, and each classification opens the file "+
			"again", n, racers)
	}
}

// TestAnEmptyPathIsNeverAdmitted: an event with no path has nothing to classify, and admitting it
// would let every such event share one cache key.
func TestAnEmptyPathIsNeverAdmitted(t *testing.T) {
	s, _ := newTestSuppressor(t, time.Minute, time.Hour, 16)
	if s.Admit("") {
		t.Error("an empty path was admitted for asynchronous classification")
	}
}
