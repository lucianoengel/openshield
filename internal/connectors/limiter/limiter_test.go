package limiter

import (
	"testing"
	"time"
)

// NIPS-7: the limiter admits a burst, then blocks until tokens refill at the sustained rate — a
// flood cannot admit faster than the configured rate.
func TestLimiterBurstAndRefill(t *testing.T) {
	base := time.Unix(1700000000, 0)
	clock := base
	l := New(10, 3) // 10/sec sustained, burst 3
	l.SetClock(func() time.Time { return clock })

	// Burst of 3 admitted immediately, the 4th blocked (no time elapsed).
	for i := 0; i < 3; i++ {
		if !l.Allow() {
			t.Fatalf("burst event %d was blocked", i)
		}
	}
	if l.Allow() {
		t.Fatal("a 4th event was admitted with no refill — the burst is not bounded")
	}

	// After 0.1s at 10/sec, exactly one token refills → one more admitted, then blocked again.
	clock = base.Add(100 * time.Millisecond)
	if !l.Allow() {
		t.Fatal("an event was not admitted after a refill interval")
	}
	if l.Allow() {
		t.Fatal("two events admitted from one refill token")
	}
}
