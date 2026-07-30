//go:build linux

package x11_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
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

func startX(t *testing.T, display string) {
	t.Helper()
	xvfb := exec.Command("Xvfb", display, "-screen", "0", "640x480x8")
	if err := xvfb.Start(); err != nil {
		t.Skipf("could not start Xvfb: %v", err)
	}
	t.Cleanup(func() { _ = xvfb.Process.Kill(); _, _ = xvfb.Process.Wait() })
	time.Sleep(800 * time.Millisecond)
}

// copyWith runs a real `xclip -i`, which OWNS the selection until something takes it away.
func copyWith(t *testing.T, display, text string) *exec.Cmd {
	t.Helper()
	c := exec.Command("xclip", "-selection", "clipboard", "-i")
	c.Env = append(os.Environ(), "DISPLAY="+display)
	in, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("xclip -i: %v", err)
	}
	_, _ = in.Write([]byte(text))
	_ = in.Close()
	t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() })
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
	c := exec.CommandContext(ctx, "xclip", "-selection", "clipboard", "-o")
	c.Env = append(os.Environ(), "DISPLAY="+display)
	out, _ := c.Output() // refused: non-zero exit with no output, or no answer at all and we time out
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
