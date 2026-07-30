//go:build linux

package x11_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard/x11"
)

// The REAL enforcement proof for DLP-2a increment 2, headless on Xvfb.
//
// Everything here is real: a real X server, a real copy by a real client (`xclip -i`), our real mediator
// taking ownership, and a real paste attempt by a SEPARATE process (`xclip -o`) that either receives the
// content or does not, according to the policy decision. Nothing is simulated — this is the claim
// "the paste is decided at paste time" executed end to end.
//
// Gated: needs Xvfb + xclip, so it skips on the dev workstation and in ordinary CI and runs on the rooted VM.
func requireX(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"Xvfb", "xclip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("X11 mediation test needs %s; skipping", bin)
		}
	}
}

// KILLING THE CHILD IS NOT ENOUGH, and the cost of learning that was two CPU cores pinned at 100% for an
// hour on the developer's workstation.
//
// `xclip` on PATH here is a SHELL WRAPPER that sets LD_LIBRARY_PATH and execs the real binary. Kill the
// process the way `cmd.Process.Kill()` does — one pid, the direct child — and anything that has not yet
// been replaced by the exec, or that the exec'd binary itself spawned, survives. It survives ORPHANED, with
// its parent gone, and then Xvfb is killed by this very cleanup and the orphan spins forever on a dead X
// connection. Two of them were found at PPID 1 having each burned 62 minutes of CPU in 63 minutes of
// wall-clock — a busy loop, not a wait.
//
// So every child is put in its OWN PROCESS GROUP and the whole group is signalled. That is correct
// regardless of whether the wrapper had exec'd yet, and regardless of what the real binary forks.
//
// It leaked from FAILING runs specifically, which is the worst case: a red test that also wedges the
// machine it ran on is one people stop running.
func setpgid(c *exec.Cmd) *exec.Cmd {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return c
}

// killGroup signals the process GROUP, then the process, then reaps. Every step is best-effort: the group
// may already be gone, and a cleanup that failed loudly on an already-dead child would turn tidy teardown
// into test noise.
func killGroup(c *exec.Cmd) {
	if c == nil || c.Process == nil {
		return
	}
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	_ = c.Process.Kill()
	_, _ = c.Process.Wait()
}

func startX(t *testing.T, display string) {
	t.Helper()
	xvfb := setpgid(exec.Command("Xvfb", display, "-screen", "0", "640x480x8"))
	if err := xvfb.Start(); err != nil {
		t.Skipf("could not start Xvfb: %v", err)
	}
	// Registered FIRST, so it runs LAST: t.Cleanup is LIFO, and every xclip must be gone before the display
	// it is talking to disappears. Reverse the order and each surviving client is handed a dead connection,
	// which is precisely the busy loop described above.
	t.Cleanup(func() { killGroup(xvfb) })
	time.Sleep(800 * time.Millisecond)
}

// KNOWN RED ON ONE WORKSTATION, AND DELIBERATELY LEFT THAT WAY.
//
// requireX checks that Xvfb and xclip EXIST, which is not the same as "this X environment can carry a
// clipboard". On the luciano-desktop `coder` account, `xclip` resolves to a wrapper under ~/.local/x11 that
// starts fine but cannot complete a selection transfer, so both tests here fail with empty content —
// which reads exactly like "the mediator refused a paste it should have allowed". It is not a product
// failure: the same tests PASS with the distribution's xclip on the rooted VM.
//
// AN ENVIRONMENT PREFLIGHT WAS TRIED AND REVERTED, and the reason is worth keeping. A probe that ran plain
// xclip against plain xclip and skipped when the round trip failed looked airtight — no product code in
// the path, so it could not mask a real bug. In practice the probe itself was unreliable on a cold Xvfb:
// across five VM runs it skipped TestMediatorEnforcesPerDestination three times, a test that passes. A
// flaky gate that SKIPS is worse than the red test it replaces, because a skip is invisible and a failure
// is not. Retrying against a 12-second deadline did not fix it.
//
// So the honest state is recorded here rather than papered over with a gate that lies: verify this package
// on the VM, and treat a workstation failure as environmental until a VM run says otherwise.

// copyWith runs a real `xclip -i`, which OWNS the selection until something takes it away.
func copyWith(t *testing.T, display, text string) *exec.Cmd {
	t.Helper()
	c := setpgid(exec.Command("xclip", "-selection", "clipboard", "-i"))
	c.Env = append(os.Environ(), "DISPLAY="+display)
	in, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("xclip -i: %v", err)
	}
	// Registered BEFORE the writes, not after. A t.Fatal between Start and Cleanup — which is exactly what
	// a failing assertion does — would otherwise leave this process running with nothing scheduled to
	// reap it. The leak was found after a run in which these tests FAILED.
	t.Cleanup(func() { killGroup(c) })
	_, _ = in.Write([]byte(text))
	_ = in.Close()
	return c
}

// pasteWith runs a real `xclip -o` — a SEPARATE process asking for the clipboard. What it receives is the
// enforcement outcome.
// BOUNDED, and it was not. The comment above used to end "a refused conversion makes xclip exit non-zero
// with no output", which is one of the two ways a refusal appears. The other is NO RESPONSE AT ALL: an X11
// selection owner that does not answer a conversion request leaves the requester waiting, and `xclip -o`
// waits forever. So the DENY assertion — "a refused paste receives nothing" — was implemented as "block
// until something else gives up", and that something else was Go's 10-minute test timeout.
//
// Observed, not theorised: this package HUNG a full-module coverage sweep with `xclip -selection clipboard
// -o` blocked, and then reported 0% — which reads exactly like "skipped, needs a display". It does not skip
// here; Xvfb and xclip are both present. It hangs.
//
// A denial is now "no content within pasteTimeout" — the same observation with a bound on it. Generous
// relative to a working conversion (milliseconds), so it cannot turn a slow ALLOW into a false DENY.
const pasteTimeout = 5 * time.Second

func pasteWith(t *testing.T, display string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), pasteTimeout)
	defer cancel()
	c := setpgid(exec.CommandContext(ctx, "xclip", "-selection", "clipboard", "-o"))
	c.Env = append(os.Environ(), "DISPLAY="+display)
	// CommandContext's default cancel kills ONE pid. Through the wrapper script that is not necessarily the
	// process doing the blocking, so the timeout could fire, Output could return, and the real xclip could
	// carry on waiting on a selection owner that will never answer.
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = time.Second
	out, _ := c.Output() // refused: non-zero exit with no output, or no answer at all and we time out
	killGroup(c)         // belt and braces: nothing from this paste outlives the call
	return string(out)
}

// TestMediatorEnforcesPerDestination is the ticket's headline claim.
//
// Mutation: ignore the Decide callback and always serve → the DENY case receives the content → FAILS.
func TestMediatorEnforcesPerDestination(t *testing.T) {
	requireX(t)
	const display = ":95"
	startX(t, display)

	const secret = "CPF 529.982.247-25 mediated"
	var (
		mu        sync.Mutex
		verdict   = x11.Allow
		sawDest   string
		sawSrc    string
		sawSrcPID int
		requests  int
	)

	m, err := x11.Open(display)
	if err != nil {
		t.Skipf("cannot mediate on %s: %v", display, err)
	}
	m.Logf = func(format string, a ...any) { t.Logf("mediator: "+format, a...) }
	m.OnCopy = func(c x11.Copy) bool {
		mu.Lock()
		sawSrc, sawSrcPID = c.SourceExe, c.SourcePID
		mu.Unlock()
		return strings.Contains(string(c.Content), "CPF") // "sensitive" → mediate it
	}
	m.Decide = func(tr x11.Transfer) x11.Decision {
		mu.Lock()
		defer mu.Unlock()
		requests++
		sawDest = tr.DestExe
		return verdict
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	// A real application copies something sensitive.
	copyWith(t, display, secret)
	time.Sleep(1200 * time.Millisecond) // capture + classification + ownership takeover

	// ALLOWED destination: the paste receives the content.
	if got := pasteWith(t, display); !strings.Contains(got, "529.982.247-25") {
		t.Fatalf("an ALLOWED paste received %q, want the content — mediation must not break legitimate "+
			"pastes, or users disable the product", got)
	}

	// DENIED destination: the same content, refused.
	mu.Lock()
	verdict = x11.Deny
	mu.Unlock()
	if got := pasteWith(t, display); strings.Contains(got, "529.982.247-25") {
		t.Fatalf("a DENIED paste still received the content (%q) — the policy decision was not enforced", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests < 2 {
		t.Errorf("the decision callback saw %d paste requests, want at least 2 (allow + deny)", requests)
	}
	// Destination attribution: the pasting process was a real xclip.
	if !strings.Contains(sawDest, "xclip") {
		t.Errorf("destination attribution = %q, want the pasting xclip — per-destination policy needs it", sawDest)
	}
	// Source attribution: the PID must always resolve (the X server tells us reliably). The executable name
	// may not, because `xclip -i` forks and the original process exits before /proc can be read — a real
	// race, and the shape a deliberate evasion takes, so the pid alone is the honest guarantee here.
	if sawSrcPID <= 0 {
		t.Errorf("source pid = %d, want the copying process — X-Resource resolves this reliably", sawSrcPID)
	}
	t.Logf("source=%q (pid %d) destination=%q requests=%d", sawSrc, sawSrcPID, sawDest, requests)
}

// TestRelinquishLeavesAWorkingClipboard is the D17 property, tested against the hazard that actually
// exists: a mediator that stops MEDIATING while still connected. Closing the connection is safe either way
// (the X server releases a departing client's selections for it), so a shutdown test proves nothing — the
// first version of this test passed even with the relinquish removed, which is why it now stops mediation
// explicitly and keeps the connection open.
//
// HONEST LIMIT OF THIS TEST: it proves the end-to-end property (a stopped mediator leaves a usable
// clipboard) but it does NOT isolate the explicit relinquish. Retaining ownership while stopped was tried
// as a mutation and this test still PASSED — because the next real copy takes the selection away from us
// anyway, so normal behaviour returns either way. What the relinquish actually buys is that the previously
// mediated content is released immediately rather than at the next copy.
//
// The mutation this DOES catch: remove the `stopped` check in onOwnerChanged, so the mediator keeps
// mediating after being told to stop → the copy below is re-mediated and denied → FAILS.
func TestStopMediatingLeavesAWorkingClipboard(t *testing.T) {
	requireX(t)
	const display = ":94"
	startX(t, display)

	m, err := x11.Open(display)
	if err != nil {
		t.Skipf("cannot mediate on %s: %v", display, err)
	}
	m.Logf = func(format string, a ...any) { t.Logf("mediator: "+format, a...) }
	m.OnCopy = func(x11.Copy) bool { return true } // mediate everything so it definitely owns the selection
	m.Decide = func(x11.Transfer) x11.Decision { return x11.Deny }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	copyWith(t, display, "mediated and denied")
	time.Sleep(1000 * time.Millisecond)
	if got := pasteWith(t, display); strings.Contains(got, "mediated and denied") {
		t.Fatal("the mediator was not actually enforcing before the relinquish, so this test proves nothing")
	}

	// Stop mediating, WITHOUT tearing down the connection — the real hazard. Relinquishing alone is not
	// enough and the first version of this test proved it: the mediator kept running, re-took ownership on
	// the very next copy, and denied it. Stopping is an explicit operation.
	m.StopMediating()
	time.Sleep(300 * time.Millisecond)

	// An ordinary copy/paste round trip must work again.
	copyWith(t, display, "after relinquish")
	time.Sleep(800 * time.Millisecond)
	if got := pasteWith(t, display); !strings.Contains(got, "after relinquish") {
		t.Fatalf("after mediation was stopped, a normal copy/paste returned %q — a monitor that stops mediating "+
			"must not keep the user's clipboard hostage (D17)", got)
	}
}
