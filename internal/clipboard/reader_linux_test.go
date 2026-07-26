//go:build linux

package clipboard_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
)

// TestNewReaderRefusesWithoutADisplay: the producer's disable-loudly path starts here.
func TestNewReaderRefusesWithoutADisplay(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	_, err := clipboard.NewReader()
	if !errors.Is(err, clipboard.ErrNoHelper) {
		t.Fatalf("err = %v, want ErrNoHelper naming the missing display", err)
	}
	if !strings.Contains(err.Error(), "DISPLAY") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

// TestNewReaderResolvesTheHelper: with a display present the reader resolves a real binary once, so a
// missing helper is one clear failure at startup rather than an error per poll forever.
func TestNewReaderResolvesTheHelper(t *testing.T) {
	if _, err := exec.LookPath("xclip"); err != nil {
		t.Skip("xclip not installed on this host")
	}
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":99") // need not exist: construction only resolves the binary
	r, err := clipboard.NewReader()
	if err != nil {
		t.Fatalf("NewReader with a display and xclip present: %v", err)
	}
	if r.DisplayServer() != clipboard.DisplayX11 {
		t.Errorf("DisplayServer = %q, want x11", r.DisplayServer())
	}
}

// TestReadIsCappedAtMaxBytes runs a REAL subprocess that floods stdout, so the cap is proven against an
// actual pipe rather than a fake. A clipboard can hold megabytes and this process forwards what it reads.
//
// Mutation: remove the io.LimitReader cap → the read returns far more than MaxBytes → this FAILS.
func TestReadIsCappedAtMaxBytes(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	// A fake "clipboard helper" on PATH that writes 4 MiB.
	dir := t.TempDir()
	helper := dir + "/xclip"
	script := "#!/bin/sh\nexec head -c 4194304 /dev/zero\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":99")

	r, err := clipboard.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(b) != clipboard.MaxBytes {
		t.Fatalf("read %d bytes, want exactly MaxBytes (%d) — an unbounded read is a memory-exhaustion "+
			"primitive driven by whatever the user copied", len(b), clipboard.MaxBytes)
	}
}

// TestEmptySelectionIsNotAnError: `xclip -o` exits non-zero on an unowned selection, which is the ordinary
// state of a fresh session. Treating that as a failure would log an error every poll on a machine where
// nobody has copied anything yet.
func TestEmptySelectionIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	helper := dir + "/xclip"
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":99")

	r, err := clipboard.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Read(context.Background())
	if err != nil {
		t.Fatalf("an empty/unowned selection was reported as an error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("read %d bytes from an empty selection", len(b))
	}
}
