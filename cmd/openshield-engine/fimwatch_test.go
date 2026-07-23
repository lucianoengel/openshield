package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/fanotify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

func TestFimWatchDirs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.conf")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got := fimWatchDirs([]string{file, sub, file}) // file → parent (dir), sub → itself, dup file
	// Expect {dir (parent of file), sub}, deduped.
	want := map[string]bool{dir: true, sub: true}
	if len(got) != 2 {
		t.Fatalf("fimWatchDirs = %v, want 2 dirs (%v)", got, want)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected watch dir %q", d)
		}
	}
}

// requireFanotify skips unless unprivileged fanotify NOTIFY works here (a restricted sandbox may
// forbid it). Gated like the other kernel-facing tests.
func requireFanotify(t *testing.T) {
	t.Helper()
	w, err := fanotify.Open(t.TempDir())
	if err != nil {
		t.Skipf("unprivileged fanotify unavailable: %v", err)
	}
	w.Close()
}

// drainFor collects drift events arriving within d.
func drainFor(events <-chan *corev1.Event, d time.Duration) []*corev1.Event {
	var out []*corev1.Event
	deadline := time.After(d)
	for {
		select {
		case ev := <-events:
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

// TestFimRealtimeDetectsModify: a content change to a baselined file produces a drift event quickly
// (real-time), well within any realistic poll interval — triggered by the fanotify event, confirmed by
// the hash. A timestomped edit (restored mtime, same size) is still detected.
//
// Mutation (the trigger loop never scans): no drift arrives → this test FAILs.
func TestFimRealtimeDetectsModify(t *testing.T) {
	requireFanotify(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "critical.conf")
	if err := os.WriteFile(file, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(file)
	orig := fi.ModTime()

	baseline, _, err := fim.BuildBaseline([]string{file}, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan *corev1.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fimWatchSource(ctx, baseline, []string{file}, fim.Options{}, 100*time.Millisecond, events, discardLogger())
	time.Sleep(200 * time.Millisecond) // let the watch arm

	// Timestomp the edit: same length, restored mtime — only the content (hash) differs.
	if err := os.WriteFile(file, []byte("BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, orig, orig); err != nil {
		t.Fatal(err)
	}

	got := drainFor(events, 3*time.Second)
	found := false
	for _, ev := range got {
		if ev.GetKind() == corev1.EventKind_EVENT_KIND_FILE_MODIFIED {
			found = true
		}
	}
	if !found {
		t.Fatalf("no real-time FILE_MODIFIED drift within 3s (got %d events) — real-time detection failed", len(got))
	}
}

// TestFimRealtimeNoDriftOnNoChange: a change EVENT on a watched file whose content is unchanged (an
// identical rewrite) yields NO drift — the baseline scan confirms it, not the raw fanotify event.
//
// Mutation (emit a drift on the raw event without scanning): a no-content-change event false-drifts →
// this test FAILs.
func TestFimRealtimeNoDriftOnNoChange(t *testing.T) {
	requireFanotify(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "steady.conf")
	if err := os.WriteFile(file, []byte("STEADY"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, _, _ := fim.BuildBaseline([]string{file}, fim.Options{})

	events := make(chan *corev1.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fimWatchSource(ctx, baseline, []string{file}, fim.Options{}, 100*time.Millisecond, events, discardLogger())
	time.Sleep(200 * time.Millisecond)

	// Rewrite the SAME content — a fanotify modify event fires, but the hash is unchanged.
	if err := os.WriteFile(file, []byte("STEADY"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := drainFor(events, 1500*time.Millisecond); len(got) != 0 {
		t.Fatalf("a no-content-change event produced %d drift events — the scan must confirm drift, not the raw event", len(got))
	}
}
