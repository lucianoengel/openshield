//go:build integration && linux

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// CLIPBOARD SOURCE EXCLUSIONS, on a real X server (DLP-2a, OPENSHIELD_CLIPBOARD_EXCLUDE).
//
// The claim is a privacy one and it is stronger than "we do not alert on it": an excluded source's copy
// is NEVER READ. A password manager puts a credential on the clipboard; a DLP agent that reads it and
// then decides not to report it has still ingested the credential, and the place it ingested it into is
// a security product's memory. The exclusion is applied BEFORE the read for that reason.
//
// It needs a real X server, because the source is identified from the SELECTION OWNER — window to PID to
// executable — and there is no way to fake that without an X server and two differently-named owners.
// Which is why it had never been tested: the build host has no working X toolchain, and CI has none at
// all. It runs on the VM.

// xServer starts an Xvfb and returns its display, or skips.
func xServer(t *testing.T, display string) string {
	t.Helper()
	for _, bin := range []string{"Xvfb", "xclip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("the clipboard scenarios need %s (Xvfb + xclip); skipping", bin)
		}
	}
	// A stale lock from a killed run makes the next Xvfb exit immediately, and the failure then surfaces
	// as a clipboard fault rather than a display one — the trap D324 recorded.
	lock := filepath.Join(os.TempDir(), ".X"+display[1:]+"-lock")
	_ = os.Remove(lock)

	xvfb := exec.Command("Xvfb", display, "-screen", "0", "640x480x8")
	if err := xvfb.Start(); err != nil {
		t.Skipf("could not start Xvfb: %v", err)
	}
	t.Cleanup(func() {
		_ = xvfb.Process.Signal(syscall.SIGTERM) // SIGTERM so Xvfb removes its own lock
		done := make(chan struct{})
		go func() { _, _ = xvfb.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = xvfb.Process.Kill()
			<-done
		}
		_ = os.Remove(lock)
	})
	time.Sleep(700 * time.Millisecond)
	if err := xvfb.Process.Signal(syscall.Signal(0)); err != nil {
		t.Skipf("Xvfb exited immediately on %s (%v)", display, err)
	}

	// The toolchain must actually round-trip before anything is asserted about our reader — a half-working
	// xclip accepts a write, stays alive and never serves the selection, which reads as our bug (D324).
	env := append(os.Environ(), "DISPLAY="+display)
	probe := exec.Command("xclip", "-selection", "clipboard", "-i")
	probe.Env = env
	in, _ := probe.StdinPipe()
	if err := probe.Start(); err != nil {
		t.Skipf("xclip would not run on %s: %v", display, err)
	}
	_, _ = in.Write([]byte("probe"))
	_ = in.Close()
	t.Cleanup(func() { _ = probe.Process.Kill(); _, _ = probe.Process.Wait() })
	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	readBack := exec.CommandContext(ctx, "xclip", "-selection", "clipboard", "-o")
	readBack.Env = env // the READER needs DISPLAY too — omitting it makes a working toolchain look broken
	out, err := readBack.Output()
	if err != nil || string(out) != "probe" {
		t.Skipf("the X toolchain on this host cannot round-trip a selection (got %q, err %v)", out, err)
	}
	return display
}

// ownClipboard puts content on the clipboard using a COPY of xclip under a chosen name, so the selection
// owner's executable basename is what the exclusion matches on. It stays alive holding the selection.
func ownClipboard(t *testing.T, dir, asName, display, content string) {
	t.Helper()
	src, err := os.ReadFile("/usr/bin/xclip")
	if err != nil {
		t.Skipf("reading xclip: %v", err)
	}
	bin := filepath.Join(dir, asName)
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-selection", "clipboard", "-i")
	cmd.Env = append(os.Environ(), "DISPLAY="+display)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("owning the clipboard as %s: %v", asName, err)
	}
	if _, err := in.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	time.Sleep(500 * time.Millisecond)
}

// TestPolledClipboardCannotHonourSourceExclusions is the uncomfortable half, and it is the one an
// operator most needs to know.
//
// In the DEFAULT polled-helper mode the selection OWNER is not knowable, so a copy has no attributable
// source — and an unattributable source is deliberately NOT excluded, because excluding every
// unattributable copy would silently disable clipboard monitoring while appearing to work. Measured on a
// real X server: the engine reports `source-attribution=false`, and a copy from a binary named
// `passwordmanager` IS read.
//
// That is the documented design. What it means in practice is that `OPENSHIELD_CLIPBOARD_EXCLUDE` has no
// effect in this mode, which the setting's own description did not say (D335). This scenario pins the
// behaviour AND the disclosure, so the two cannot drift apart again.
func TestPolledClipboardCannotHonourSourceExclusions(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	display := xServer(t, ":96")

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CLIPBOARD_INTERVAL=300ms",
		"OPENSHIELD_CLIPBOARD_EXCLUDE=passwordmanager",
		"DISPLAY=" + display,
		"WAYLAND_DISPLAY=",
	})
	eng.WaitForOutput("clipboard capabilities", 90*time.Second)

	// THE DISCLOSURE MUST BE THERE. An operator setting an exclusion in this mode is relying on
	// something that does not work; the capability report is where they can find that out.
	if !contains(eng.Output(), "source-attribution=false") {
		t.Errorf("the polled clipboard did not report source-attribution=false. Without that disclosure "+
			"an operator configuring OPENSHIELD_CLIPBOARD_EXCLUDE has no way to learn it has no "+
			"effect\n%s", eng.Output())
	}

	pool := openPool(t, stack.DSN)
	entries := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	time.Sleep(3 * time.Second)
	before := entries()

	ownClipboard(t, work, "passwordmanager", display, "hunter2-the-actual-password")
	Eventually(t, 30*time.Second, "the copy to be captured DESPITE the exclusion", func() bool {
		return entries() > before
	})
	t.Log("polled mode reads an excluded source's copy — documented, and the reason mediation exists")
}

// TestMediationSaysWhenACopyHasNoAttributableSource (D335).
//
// Under mediation the capability report says `source-attribution=true`, and that is true of the
// MECHANISM rather than of every copy: attribution reads the owner window's pid, and a window that
// advertises none (`_NET_WM_PID` absent) yields no source at all. An unattributable source is
// deliberately not excluded — excluding every one would silently disable monitoring — so the copy IS
// read and `OPENSHIELD_CLIPBOARD_EXCLUDE` cannot apply to it.
//
// That was silent. The copy was read, the exclusion did not fire, and nothing said so; an operator
// relying on the exclusion had no way to learn it had not applied. The engine now says it per copy, and
// this pins the disclosure against a real X server — which is the only place the difference between "the
// mechanism is available" and "this copy was attributable" is observable at all.
func TestMediationSaysWhenACopyHasNoAttributableSource(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	display := xServer(t, ":95")

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CLIPBOARD_INTERVAL=300ms",
		"OPENSHIELD_CLIPBOARD_EXCLUDE=passwordmanager",
		"OPENSHIELD_CLIPBOARD_MEDIATE=1",
		"DISPLAY=" + display,
		"WAYLAND_DISPLAY=",
	})
	eng.WaitForOutput("clipboard MEDIATION ACTIVE", 90*time.Second)

	// A copy from an owner that advertises no pid — which is what xclip is, and what any minimal X client
	// is. Sensitive content, so mediation engages and the source question is actually asked.
	ownClipboard(t, work, "passwordmanager", display, "name,cpf\nalice,111.444.777-35\n")

	Eventually(t, 60*time.Second, "the engine to report that the copy had no attributable source", func() bool {
		return contains(eng.Output(), "NO attributable source")
	})

	// And it is honest about the consequence rather than implying the exclusion applied.
	if !contains(eng.Output(), "source exclusions cannot apply") {
		t.Errorf("the engine reported an unattributable copy without saying that exclusions cannot apply "+
			"to it. That is the whole operator-visible consequence: they configured an exclusion, it did "+
			"not fire, and the copy was read\n%s", eng.Output())
	}
}
