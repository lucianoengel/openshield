//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// On Linux, openFileWatcher must use the fanotify connector (D52) and return a
// working watcher — a created file surfaces an Event. Guards a mutation that
// returns nil or a broken watcher from the Linux seam.
func TestOpenFileWatcherLinuxObserves(t *testing.T) {
	dir := t.TempDir()
	w, err := openFileWatcher(dir)
	if err != nil {
		t.Skipf("fanotify unavailable in this environment: %v", err)
	}
	if w == nil {
		t.Fatal("openFileWatcher returned a nil watcher")
	}
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := os.WriteFile(filepath.Join(dir, "n.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.GetFilesystem().GetResolvedPath() == "" {
		t.Errorf("event carries no path: %+v", ev)
	}
}
