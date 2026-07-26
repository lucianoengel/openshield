//go:build linux

package clipboard_test

import (
	"context"
	"os"
	"os/exec"
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
	xvfb := exec.Command("Xvfb", display, "-screen", "0", "640x480x8")
	if err := xvfb.Start(); err != nil {
		t.Skipf("could not start Xvfb: %v", err)
	}
	t.Cleanup(func() {
		_ = xvfb.Process.Kill()
		_, _ = xvfb.Process.Wait()
	})
	// Give the server a moment to accept connections.
	time.Sleep(700 * time.Millisecond)

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
