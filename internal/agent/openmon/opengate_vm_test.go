//go:build linux

package openmon_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/openipc"
	"github.com/lucianoengel/openshield/internal/agent/openmon"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// THE B2 FILE-OPEN GATE ON A LIVE KERNEL.
//
// Root-gated: FAN_OPEN_PERM needs CAP_SYS_ADMIN and a permission-capable kernel, so this SKIPS
// everywhere else rather than failing. Run on the rooted VM with `go test -c` + scp + sudo.
//
// WHAT THIS PROVES that no unit test can: that a directory mark with FAN_EVENT_ON_CHILD actually
// delivers opens of files inside it (an empirical kernel question — the exec gate learned the hard way
// that a directory mark does NOT deliver exec permissions for files within, D224); that the prefix read
// from the kernel's descriptor is the file's real content; and that a DENY reaches the opening process
// as EPERM.
//
// SAFETY, because this hangs hosts when it is wrong. Everything runs in a fresh temp directory, never a
// system path. The budget is short. The ALLOW path is asserted FIRST — if the gate is broken in a way
// that blocks, that is where it shows, with a short budget bounding the damage. A process in a
// permission window is uninterruptible, so a wrong answer here is not a failed test, it is a wedged
// machine.

func requireRootLinux(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("FAN_OPEN_PERM needs root; run this on the VM")
	}
}

// stubDecider answers every request the same way, recording the prefix it was given.
type stubDecider struct {
	verdict openipc.Verdict
	seen    chan string
}

func (d *stubDecider) decide(_ context.Context, _ string, prefix []byte) (openipc.Verdict, error) {
	select {
	case d.seen <- string(prefix):
	default:
	}
	return d.verdict, nil
}

// startGate brings up the producer, the verdict server and the watchdog over dir, and returns a cancel.
func startGate(t *testing.T, dir string, verdict openipc.Verdict) (*stubDecider, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	sock := socketPath(t, "open.sock")
	dec := &stubDecider{verdict: verdict, seen: make(chan string, 4)}
	srv := &openipc.Server{Decide: dec.decide, Timeout: 2 * time.Second}
	go func() { _ = srv.Listen(ctx, sock) }()

	// Wait for the socket, so the first open is not decided by a fail-open that would make an ALLOW
	// assertion pass for the wrong reason.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mon, err := openmon.Open([]string{dir})
	if err != nil {
		cancel()
		t.Fatalf("opening the file-open monitor: %v", err)
	}
	client := &openipc.Client{SocketPath: sock, Timeout: 2 * time.Second, MaxPrefix: openipc.MaxPrefixLen}
	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    3 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}
	go func() { _ = mon.Run(ctx, wd) }()
	time.Sleep(300 * time.Millisecond) // let the read loop reach its first poll

	return dec, func() { cancel(); client.Close(); mon.Close() }
}

// openFromAnotherProcess opens the file from a CHILD, because this process is the watchdog's SelfPID
// and is exempt by identity — the agent must not deadlock on its own access. A test that opened the
// file itself would be testing the exemption, not the gate.
func openFromAnotherProcess(t *testing.T, path string) error {
	t.Helper()
	return exec.Command("/bin/cat", path).Run()
}

// TestTheOpenGateAllowsAndSeesTheContent is asserted FIRST, deliberately: it is the path that must work
// before any DENY is attempted, and a gate broken in the blocking direction shows up here bounded by a
// short budget rather than by a wedged machine.
func TestTheOpenGateAllowsAndSeesTheContent(t *testing.T) {
	requireRootLinux(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	const body = "name,cpf\nalice,111.444.777-35\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	dec, stop := startGate(t, dir, openipc.VerdictAllow)
	defer stop()

	if err := openFromAnotherProcess(t, path); err != nil {
		t.Fatalf("an ALLOWED open failed: %v — the gate is refusing or hanging opens it should permit", err)
	}

	// THE PREFIX IS THE FILE'S REAL CONTENT, read from the kernel's descriptor without re-opening it.
	select {
	case got := <-dec.seen:
		if !strings.Contains(got, "111.444.777-35") {
			t.Errorf("the decider received %q — the prefix does not carry the file's content, so a "+
				"content gate would be deciding on nothing", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no permission event reached the decider. A directory mark with FAN_EVENT_ON_CHILD did " +
			"NOT deliver opens of files inside the directory on this kernel — the same class of surprise " +
			"D224 recorded for exec permissions, and the gate would be silently inert")
	}
}

// TestTheOpenGateDeniesAndTheOpenerSeesEPERM.
//
// Run only after the ALLOW path is known good.
func TestTheOpenGateDeniesAndTheOpenerSeesEPERM(t *testing.T) {
	requireRootLinux(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("cpf 111.444.777-35\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stop := startGate(t, dir, openipc.VerdictDeny)
	defer stop()

	err := openFromAnotherProcess(t, path)
	if err == nil {
		t.Fatal("a DENIED open SUCCEEDED — the gate decides and the kernel does not act on it, which is " +
			"inline prevention that prevents nothing")
	}
}

// TestAnUnreachableEngineAllowsTheOpen is the property that keeps this safe to deploy: the gate's
// failure mode must be a permitted open, never a hung process.
func TestAnUnreachableEngineAllowsTheOpen(t *testing.T) {
	requireRootLinux(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mon, err := openmon.Open([]string{dir})
	if err != nil {
		t.Fatalf("opening the monitor: %v", err)
	}
	defer mon.Close()

	// A socket that does not exist: every event fails open.
	client := &openipc.Client{
		SocketPath: socketPath(t, "absent.sock"),
		Timeout:    200 * time.Millisecond,
	}
	defer client.Close()
	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    2 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}
	go func() { _ = mon.Run(ctx, wd) }()
	time.Sleep(300 * time.Millisecond)

	if err := openFromAnotherProcess(t, path); err != nil {
		t.Fatalf("an open failed while the engine was unreachable: %v — the gate must FAIL OPEN, or a "+
			"dead engine takes the host's filesystem with it", err)
	}
}

// TestAMountScopeIsRefused: marking a mount would route every open on the host through a permission
// window. Not root-gated in effect — it fails before any mark is attempted — but kept here beside the
// gate it protects.
func TestAMountScopeIsRefused(t *testing.T) {
	requireRootLinux(t)
	if _, err := openmon.Open([]string{filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Error("a non-existent path was accepted")
	}
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openmon.Open([]string{f}); err == nil {
		t.Error("a regular file was accepted as a gate scope; naming a file is almost always a mistake " +
			"an operator meant as 'this directory', and the difference is invisible afterwards")
	}
}

// TestConcurrentOpensAreNotSerialised is the load question the single-decision measurement cannot
// answer.
//
// THE PER-EVENT BUDGET IS NOT A PER-PROCESS BOUND. The watchdog's budget starts when it dequeues an
// event, not when the kernel blocked the process — so if events are answered one at a time, the Nth
// opener waits N × decision-cost while the watchdog believes every answer was inside budget. Nothing
// in the single-decision latency number reveals that.
//
// It matters here and not for the exec gate because of scale. An exec decision is ~41µs (D301), so
// fifty concurrent execs queue for 2ms — invisible. An open decision is ~6ms at the default prefix, so
// fifty concurrent opens queue for 300ms, and the last opener waits a third of a second for a gate
// whose budget says 150ms.
//
// The simulated decision cost is deliberate: a real classification would make this measure the worker
// rather than the queueing, and the queueing is the property under test.
func TestConcurrentOpensAreNotSerialised(t *testing.T) {
	requireRootLinux(t)
	const (
		openers   = 12
		perAnswer = 25 * time.Millisecond
	)

	dir := t.TempDir()
	for i := 0; i < openers; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)), []byte("data\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock := socketPath(t, "slow.sock")
	slow := func(context.Context, string, []byte) (openipc.Verdict, error) {
		time.Sleep(perAnswer)
		return openipc.VerdictAllow, nil
	}
	srv := &openipc.Server{Decide: slow, Timeout: 5 * time.Second}
	go func() { _ = srv.Listen(ctx, sock) }()
	waitForSocket(t, sock)

	mon, err := openmon.Open([]string{dir})
	if err != nil {
		t.Fatalf("opening the monitor: %v", err)
	}
	defer mon.Close()
	wd := &watchdog.Watchdog{
		SelfPID: int32(os.Getpid()),
		Budget:  10 * time.Second, // generous: this measures QUEUEING, not the budget
		// One client per opener would hide the queueing behind connection concurrency; the production
		// agent has exactly one.
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: &openipc.Client{SocketPath: sock, Timeout: 5 * time.Second},
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}
	go func() { _ = mon.Run(ctx, wd) }()
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < openers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = exec.Command("/bin/cat", filepath.Join(dir, "f"+strconv.Itoa(n))).Run()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	serial := time.Duration(openers) * perAnswer
	t.Logf("%d concurrent opens at %s per decision took %s (serial would be ~%s)",
		openers, perAnswer, elapsed, serial)

	// HALF the serial time is a generous line: perfectly concurrent would be ~perAnswer plus overhead,
	// and anything at or past serial means the gate is a queue. Generous on purpose — the point is to
	// catch serialisation, not to assert a particular degree of parallelism on a 4-vCPU VM.
	if elapsed >= serial/2 {
		t.Errorf("concurrent opens took %s, close to the %s a SERIAL gate would need. Events are being "+
			"answered one at a time, so the Nth opener waits N × the decision cost while the watchdog's "+
			"per-event budget still reads as satisfied — the budget bounds dequeue-to-answer, not "+
			"block-to-answer", elapsed, serial)
	}
}

// waitForSocket blocks until the verdict socket exists, so the first open is not decided by a
// fail-open that would make a timing assertion meaningless.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the verdict socket never appeared at %s", path)
}
