//go:build linux

package openmon_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/openipc"
	"github.com/lucianoengel/openshield/internal/agent/openmon"
	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// THE ASYNC TIER'S CYCLE TERMINATES, ON A LIVE KERNEL (B2 tier 2).
//
// The second tier classifies the whole file after the gate has answered — and that classification
// OPENS the file, an open that falls under the same mark, which the gate must answer, which submits
// again. The unit tests in internal/agent/prefilter pin the suppressor's logic; what they cannot do is
// close the loop through a real fanotify mark and a real second process.
//
// WHY THIS TEST IS SHAPED THE WAY IT IS. A design that recurses does not produce a red test. It
// produces a host that stops: each opener sits in an UNINTERRUPTIBLE permission window, and a loop
// generating them faster than they are answered takes the machine with it. So the resubmission is
// HARD-CAPPED below, at a number far above what a correct implementation reaches and far below what
// hurts. The cap is what makes the mutation — remove the suppressor, watch it loop — something that
// can be run at all rather than a thing to reason about and hope.
//
// Verdicts are ALLOW throughout. A DENY would refuse the simulated classification's own open, so the
// cycle would terminate for the wrong reason and prove nothing; and per the D352 ordering that exists
// because this host was bricked twice, the allowing path is the one to establish first.

// cycleGate stands in for the engine's gate handler: it answers, and — exactly as the engine does —
// submits the path for asynchronous classification unless the suppressor declines.
type cycleGate struct {
	suppress *prefilter.PathSuppressor
	path     string

	questions atomic.Int64 // gate questions seen for path
	opens     atomic.Int64 // simulated classification opens issued
	capped    atomic.Bool  // the safety cap fired — the cycle did NOT terminate
}

// maxSimulatedOpens is the safety cap. A correct implementation issues exactly one; anything past a
// handful is the loop, and stopping here is what keeps a broken implementation a failed test rather
// than a wedged machine.
const maxSimulatedOpens = 20

func (g *cycleGate) decide(_ context.Context, path string, _ []byte) (openipc.Verdict, error) {
	if path != g.path {
		return openipc.VerdictAllow, nil
	}
	g.questions.Add(1)

	if !g.suppress.Admit(path) {
		return openipc.VerdictAllow, nil
	}
	if g.opens.Add(1) > maxSimulatedOpens {
		// STOP FEEDING THE LOOP. Everything after this point would be more blocked processes.
		g.capped.Store(true)
		g.suppress.Done(path)
		return openipc.VerdictAllow, nil
	}
	// The submission is asynchronous in the engine too: it enqueues and returns, because this runs
	// inside a permission window and must not block a process that the kernel has stopped.
	go func() {
		// The classification's own open, from ANOTHER process — the engine's sandboxed worker does the
		// open, not the engine. That is the whole reason the cycle breaker is keyed on the path and not
		// on a PID: the process on the verdict socket is not the process that opens.
		_ = exec.Command("/bin/cat", path).Run()
		// Done only AFTER the open it caused has been decided, which is what makes the suppression
		// cover the gap however slow the classification is.
		g.suppress.Done(path)
	}()
	return openipc.VerdictAllow, nil
}

// TestTheAsyncSubmissionCycleTerminates.
func TestTheAsyncSubmissionCycleTerminates(t *testing.T) {
	requireRootLinux(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "classified.csv")
	if err := os.WriteFile(path, []byte("name,cpf\nalice,111.444.777-35\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &cycleGate{
		// The REAL suppressor, with the production defaults for the hold and the ceiling. A stub that
		// returned false would make this test pass against any design at all.
		suppress: prefilter.NewPathSuppressor(30*time.Second, 0, 0),
		path:     path,
	}
	sock := socketPath(t, "cycle.sock")
	srv := &openipc.Server{Decide: g.decide, Timeout: 2 * time.Second}
	go func() { _ = srv.Listen(ctx, sock) }()
	waitForSocket(t, sock)

	mon, err := openmon.Open([]string{dir})
	if err != nil {
		t.Fatalf("opening the file-open monitor: %v", err)
	}
	defer mon.Close()
	client := &openipc.Client{SocketPath: sock, Timeout: 2 * time.Second, MaxPrefix: openipc.MaxPrefixLen}
	defer client.Close()
	wd := &watchdog.Watchdog{
		SelfPID: int32(os.Getpid()),
		// SHORT, deliberately. If the gate wedges, this is what bounds the damage to the openers rather
		// than to the machine.
		Budget:    3 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}
	go func() { _ = mon.Run(ctx, wd) }()
	time.Sleep(300 * time.Millisecond)

	// ONE ordinary open, from another process. Everything after this is the system reacting to itself.
	if err := openFromAnotherProcess(t, path); err != nil {
		t.Fatalf("the initial open failed: %v — the gate is refusing or hanging opens it should permit, "+
			"and nothing below would be measuring the cycle", err)
	}

	// Let the reaction run itself out. A terminating design is quiet within a second; this waits far
	// longer so a slow loop is caught rather than outrun.
	deadline := time.Now().Add(10 * time.Second)
	var stableSince time.Time
	last := int64(-1)
	for time.Now().Before(deadline) {
		if n := g.questions.Load(); n != last {
			last, stableSince = n, time.Now()
		} else if !stableSince.IsZero() && time.Since(stableSince) > 3*time.Second {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	questions, opens := g.questions.Load(), g.opens.Load()
	t.Logf("gate questions for the path: %d; simulated classification opens: %d", questions, opens)

	if g.capped.Load() {
		t.Fatalf("the resubmission cap of %d fired: the cycle did NOT terminate. Every asynchronous "+
			"classification opened the file, that open was gated, and answering it submitted again. "+
			"Without the cap this would not be a failing test — it would be a host filling with "+
			"processes stopped in uninterruptible permission windows", maxSimulatedOpens)
	}

	// EXACTLY ONE classification. The initial open earns it; the classification's own open must not.
	if opens != 1 {
		t.Errorf("%d asynchronous classifications were issued for one open, want exactly 1. More than "+
			"one means the classification's own open was resubmitted — a loop that happens to have "+
			"stopped, not a loop that cannot start", opens)
	}

	// AND THE GATE ANSWERED EVERY OPEN. The suppression must silence the RE-CLASSIFICATION, never the
	// verdict: a design that stopped deciding repeat opens would score perfectly above while being a
	// hole in the gate.
	if questions < 2 {
		t.Errorf("the gate saw %d questions for this path, want at least 2 (the initial open and the "+
			"classification's own). Fewer means the classification never opened the file, so the cycle "+
			"was never actually exercised and this test proves nothing", questions)
	}

	// The suppressor's own accounting must agree: the classification's open was DECLINED, not missed.
	if n := g.suppress.Suppressed(); n < 1 {
		t.Errorf("the suppressor declined %d submissions. If the second open was never offered to it, "+
			"the loop is being broken by something else — timing, most likely — and that something "+
			"will not hold under load", n)
	}
}
