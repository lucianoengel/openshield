//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// REAL-TIME FIM (HIPS-4 inc 2): OPENSHIELD_FIM_REALTIME and OPENSHIELD_FIM_DEBOUNCE.
//
// Polling FIM detects tamper up to one interval late. Against a rootkit or a privilege-escalation edit
// that is the difference between catching the change and catching its aftermath — the attacker has the
// whole interval to act, and on a default 60-second poll that is a long time on a machine.
//
// The real-time watch closes it, and the poll stays as the completeness backstop (an inotify queue can
// overflow; a poll cannot miss a file that is simply different).
//
// THE POLL IS WHAT MAKES THIS HARD TO TEST HONESTLY. With any normal interval a detection could have come
// from either source, so the scenarios below set the interval far beyond the test's lifetime: anything
// detected inside the window can only have come from the watch. The paired negative — the same setup with
// the watch OFF detecting nothing — is what proves the interval really was out of reach, rather than the
// assertion being satisfied by a poll that happened to fire.

// fimSetup builds a signed baseline over a directory holding one critical file, and returns both paths.
func fimSetup(t *testing.T, work string) (critical, guarded, baseline, pub string) {
	t.Helper()
	critical = filepath.Join(work, "critical")
	if err := os.MkdirAll(critical, 0o755); err != nil {
		t.Fatal(err)
	}
	guarded = filepath.Join(critical, "sudoers")
	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, pub := filepath.Join(work, "fim.key"), filepath.Join(work, "fim.pub")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"keygen", "--out-key", key, "--out-pub", pub); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	baseline = filepath.Join(work, "baseline.sig")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"build", "--paths", critical, "--key", key, "--out", baseline); err != nil {
		t.Fatalf("baseline: %v\n%s", err, out)
	}
	return critical, guarded, baseline, pub
}

// startFIM runs the engine with FIM configured and a poll interval far beyond the test's lifetime, so a
// detection inside the window can only have come from the real-time watch.
func startFIM(t *testing.T, stack *Stack, work, critical, baseline, pub string, extra ...string) (*Process, func() int) {
	t.Helper()
	eng := Start(t, "openshield-engine", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_FIM_PATHS=" + critical,
		"OPENSHIELD_FIM_BASELINE=" + baseline,
		"OPENSHIELD_FIM_BASELINE_PUBKEY=" + pub,
		// AN HOUR. The poll cannot be the thing that detects anything below.
		"OPENSHIELD_FIM_INTERVAL=1h",
	}, extra...))
	eng.WaitForOutput("engine observing", 90*time.Second)

	pool := openPool(t, stack.DSN)
	return eng, func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
}

// TestRealTimeFimCatchesTamperWithoutWaitingForThePoll.
func TestRealTimeFimCatchesTamperWithoutWaitingForThePoll(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	critical, guarded, baseline, pub := fimSetup(t, work)

	eng, entries := startFIM(t, stack, work, critical, baseline, pub,
		"OPENSHIELD_FIM_REALTIME=1",
		"OPENSHIELD_FIM_DEBOUNCE=200ms")
	eng.WaitForOutput("FIM real-time watch ENABLED", 60*time.Second)

	// A quiet host must stay quiet: a detector that reports without a change is one whose reports get
	// ignored, and this also fixes the baseline the assertion below measures against.
	time.Sleep(3 * time.Second)
	quiet := entries()

	// THE TAMPER — the line a privilege escalation adds.
	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	Eventually(t, 60*time.Second, "the tamper to be detected by the real-time watch", func() bool {
		return entries() > quiet
	})
	t.Logf("real-time FIM detected the change in %s (poll interval is 1h)", time.Since(start))
}

// TestWithoutRealTimeTheSameTamperWaitsForThePoll is what makes the scenario above about the WATCH.
//
// Same directory, same baseline, same hour-long interval, real-time OFF. Nothing may be detected inside
// the window — and if something is, then the poll is firing after all and the positive above proved
// nothing about `OPENSHIELD_FIM_REALTIME`.
//
// This is the pairing the webhook and overdue scenarios taught: an outcome that could have been produced
// by another layer has to be shown NOT to happen when that layer is the only one left.
func TestWithoutRealTimeTheSameTamperWaitsForThePoll(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	critical, guarded, baseline, pub := fimSetup(t, work)

	eng, entries := startFIM(t, stack, work, critical, baseline, pub) // no OPENSHIELD_FIM_REALTIME
	if contains(eng.Output(), "FIM real-time watch ENABLED") {
		t.Fatal("the real-time watch started without being configured — this scenario cannot then " +
			"distinguish the watch from the poll")
	}
	time.Sleep(3 * time.Second)
	quiet := entries()

	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Second) // comfortably longer than the real-time detection above

	if n := entries(); n > quiet {
		t.Errorf("a tamper was detected with real-time OFF and the poll an hour away (%d -> %d audit "+
			"entries). Something other than the configured sources is reporting drift, so the real-time "+
			"scenario is not measuring OPENSHIELD_FIM_REALTIME\n%s", quiet, n, eng.Output())
	}
}
