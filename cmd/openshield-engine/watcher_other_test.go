//go:build !linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// On a non-Linux OS (windows, darwin), openFileWatcher must use the PORTABLE
// watcher, not fanotify — so the engine runs and observes instead of failing with
// ErrUnsupported. Guards a mutation that wires fanotify.Open (which returns
// ErrUnsupported off Linux) into the non-Linux seam. Runs when the suite is
// executed on a non-Linux host (external-gated for execution on the Linux CI; it
// is compile-verified there via `GOOS=darwin go vet`).
func TestOpenFileWatcherNonLinuxObserves(t *testing.T) {
	dir := t.TempDir()
	w, err := openFileWatcher(dir)
	if err != nil {
		t.Fatalf("openFileWatcher must use the portable watcher off Linux, got error: %v", err)
	}
	if w == nil {
		t.Fatal("openFileWatcher returned a nil watcher")
	}
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := os.WriteFile(filepath.Join(dir, "n.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.Kind != corev1.EventKind_EVENT_KIND_FILE_CREATED {
		t.Errorf("want CREATED, got %v", ev.Kind)
	}
}
