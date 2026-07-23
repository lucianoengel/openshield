package dnsredirect

import (
	"net"
	"testing"
	"time"
)

// fakeWatchdog builds a Watchdog whose probe/install/remove are driven by the test (no root, no time).
type counters struct{ installs, removes int }

func newFakeWatchdog(failures int, probe func() bool) (*Watchdog, *counters) {
	c := &counters{}
	w := &Watchdog{
		Failures: failures,
		Probe:    probe,
		install:  func() error { c.installs++; return nil },
		remove:   func() { c.removes++ },
	}
	return w, c
}

// TestThresholdIsLoadBearing: with Failures=3, two failing steps must NOT remove; the third removes exactly
// once. Mutation (bypass after 1 failure) makes the two-step assertion fail.
func TestThresholdIsLoadBearing(t *testing.T) {
	w, c := newFakeWatchdog(3, func() bool { return false })
	w.installed = true // as if Run installed it

	w.step()
	w.step()
	if c.removes != 0 {
		t.Fatalf("after 2 failures (threshold 3) removes = %d, want 0 (a single blip must not bypass)", c.removes)
	}
	w.step()
	if c.removes != 1 {
		t.Fatalf("after 3 failures removes = %d, want exactly 1 (bypass)", c.removes)
	}
	// Further failures while already bypassed do not remove again.
	w.step()
	if c.removes != 1 {
		t.Fatalf("removes = %d after an extra failure while bypassed, want 1", c.removes)
	}
}

// TestRestoreOnRecovery: after a bypass, a passing probe re-installs exactly once and resets the counter.
func TestRestoreOnRecovery(t *testing.T) {
	alive := false
	w, c := newFakeWatchdog(2, func() bool { return alive })
	w.installed = true

	w.step() // fail 1
	w.step() // fail 2 → bypass
	if c.removes != 1 || w.installed {
		t.Fatalf("expected one bypass (removes=%d installed=%v)", c.removes, w.installed)
	}
	alive = true
	w.step() // recover → re-install
	if c.installs != 1 || !w.installed {
		t.Fatalf("recovery should re-install exactly once (installs=%d installed=%v)", c.installs, w.installed)
	}
	if w.consecutiveFailures != 0 {
		t.Fatalf("consecutiveFailures = %d after recovery, want 0 (reset)", w.consecutiveFailures)
	}
}

// TestIntermittentFailuresDoNotBypass: a fail,fail,pass,fail,fail sequence with threshold 3 must NOT bypass
// (the pass resets the counter). Mutation (never reset on a pass) makes this fail.
func TestIntermittentFailuresDoNotBypass(t *testing.T) {
	seq := []bool{false, false, true, false, false} // never 3 failures in a row
	i := 0
	w, c := newFakeWatchdog(3, func() bool { b := seq[i]; i++; return b })
	w.installed = true
	for range seq {
		w.step()
	}
	if c.removes != 0 {
		t.Fatalf("intermittent failures wrongly bypassed (removes=%d) — the counter must reset on a pass", c.removes)
	}
}

// TestDefaultProbe: true against a live stub UDP responder, false against a closed port within the timeout.
func TestDefaultProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr) // any response = alive
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if !defaultProbe(port)() {
		t.Fatal("defaultProbe against a live resolver should be true")
	}

	// A closed port: bind then release to get a port nothing listens on.
	tmp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadPort := tmp.LocalAddr().(*net.UDPAddr).Port
	tmp.Close()
	start := time.Now()
	if defaultProbe(deadPort)() {
		t.Fatal("defaultProbe against a closed port should be false")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("defaultProbe should fail within the timeout, not hang")
	}
}
