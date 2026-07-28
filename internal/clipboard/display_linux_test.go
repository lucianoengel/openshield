//go:build linux

package clipboard_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
)

// The REAL-DISPLAY test: a genuine X11 clipboard, set with xclip and read back through the shipped X11
// backend. Everything is real — the X server (Xvfb), the selection, the helper subprocess.
//
// It is GATED: it needs Xvfb + xclip, which the dev workstation does not have, so it skips there and in
// ordinary CI. It runs on the rooted VM where both are installed. That makes it a STRENGTHENING test, not
// the one the shipped claim rests on — the fake-Reader pipeline test carries that.
func TestRealX11ClipboardRoundTrip(t *testing.T) {
	for _, bin := range []string{"Xvfb", "xclip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("real-display clipboard test needs %s (install xvfb + xclip); skipping", bin)
		}
	}

	const display = ":97"
	// A STALE LOCK FROM THIS TEST'S OWN PREVIOUS RUN IS THE FAILURE MODE TO DEFEND AGAINST (D324).
	//
	// Xvfb removes /tmp/.X97-lock on a clean exit and NOT when it is killed — and the cleanup below used
	// to SIGKILL it. So one run left the lock behind, the next Xvfb refused to start on an
	// already-locked display and exited immediately, and the test then failed several seconds later with
	// "the first poll of a non-empty clipboard reported no change": a message about the clipboard, for a
	// fault in the display. It poisoned its own next run and misreported the cause, which is the pair of
	// properties that makes a failure expensive to diagnose.
	//
	// Removing a stale lock BEFORE starting is the same discipline the TPROXY and DNS-redirect rules
	// follow: delete leftovers first, so a crashed run never breaks the next one.
	lock := filepath.Join(os.TempDir(), ".X97-lock")
	if _, err := os.Stat(lock); err == nil {
		if err := os.Remove(lock); err != nil {
			t.Skipf("a stale %s is present and not removable (%v) — another user's display server may "+
				"hold %s", lock, err, display)
		}
	}

	xvfb := exec.Command("Xvfb", display, "-screen", "0", "640x480x8")
	if err := xvfb.Start(); err != nil {
		t.Skipf("could not start Xvfb: %v", err)
	}
	t.Cleanup(func() {
		// SIGTERM, not SIGKILL, so Xvfb removes its own lock. Then remove it anyway: a server that dies
		// badly must not cost the next run.
		_ = xvfb.Process.Signal(syscall.SIGTERM)
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
	// Give the server a moment to accept connections.
	time.Sleep(700 * time.Millisecond)

	// THE DISPLAY MUST ACTUALLY BE UP. Without this the test proceeds against a dead server and reports
	// its fault as a clipboard fault, which is how the stale lock stayed unexplained.
	if err := xvfb.Process.Signal(syscall.Signal(0)); err != nil {
		t.Skipf("Xvfb exited immediately on %s (%v) — the display never came up, so this scenario has "+
			"nothing to observe", display, err)
	}

	env := append(os.Environ(), "DISPLAY="+display)
	const secret = "CPF 529.982.247-25 from the real clipboard"

	// Own the CLIPBOARD selection with a real xclip, kept alive for the read (xclip exits when the
	// selection is lost, so it must outlive our read).
	set := exec.Command("xclip", "-selection", "clipboard", "-i")
	set.Env = env
	stdin, err := set.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Start(); err != nil {
		t.Skipf("could not run xclip against %s: %v", display, err)
	}
	if _, err := stdin.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	t.Cleanup(func() {
		_ = set.Process.Kill()
		_, _ = set.Process.Wait()
	})
	time.Sleep(400 * time.Millisecond)

	// THE ENVIRONMENT MUST BE ABLE TO ROUND-TRIP A SELECTION before this asserts anything about our
	// reader, and the probe is xclip reading back what xclip wrote — our code not involved.
	//
	// It is bounded by a context because the failure mode observed here is a HANG, not an error: an
	// xclip unpacked from a .deb into a home directory starts, accepts the write, stays alive, and then
	// never serves the selection. Our reader saw empty content and the test failed with "the first poll
	// of a non-empty clipboard reported no change" — a message that reads as a bug in the reader.
	//
	// Skipping on this cannot hide a regression: it fires only when the X toolchain fails before our
	// code is reached. If xclip CAN read its own selection and our reader cannot, that is a real failure
	// and it still fails. A half-working toolchain is the same situation as an absent one, which this
	// test already skips for.
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelProbe()
	probe := exec.CommandContext(probeCtx, "xclip", "-selection", "clipboard", "-o")
	probe.Env = env
	switch out, err := probe.Output(); {
	case probeCtx.Err() != nil:
		t.Skipf("xclip could not read back its OWN clipboard selection on %s within 3s (it hung) — the "+
			"X toolchain here cannot serve a selection, so there is nothing for the reader to read", display)
	case err != nil:
		t.Skipf("xclip could not read back its own clipboard selection on %s: %v", display, err)
	case string(out) != secret:
		t.Skipf("xclip read back %q from its own selection, want %q — the X toolchain here is not "+
			"round-tripping the clipboard", out, secret)
	}

	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", display)
	r, err := clipboard.NewReader()
	if err != nil {
		t.Fatalf("NewReader on a live X11 display: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Through the real Watcher, so change detection is exercised on real content too.
	w := &clipboard.Watcher{Reader: r}
	got, changed, err := w.Poll(ctx)
	if err != nil {
		t.Fatalf("polling a live X11 clipboard: %v", err)
	}
	if !changed {
		t.Fatal("the first poll of a non-empty clipboard reported no change")
	}
	if string(got) != secret {
		t.Fatalf("read %q from the real clipboard, want %q", got, secret)
	}
	// And an unchanged real clipboard does not re-report.
	if _, changed, err := w.Poll(ctx); err != nil || changed {
		t.Errorf("the second poll of an unchanged real clipboard reported changed=%v (err=%v)", changed, err)
	}
	t.Logf("real X11 clipboard round trip OK via %s: %d bytes", r.DisplayServer(), len(got))
}
