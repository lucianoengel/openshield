package filewatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// --- pure diff core (the mutation surface) ---

func TestDiffDetectsCreate(t *testing.T) {
	prev := snapshot{"a.txt": {size: 1, modNano: 10}}
	cur := snapshot{"a.txt": {size: 1, modNano: 10}, "b.txt": {size: 2, modNano: 20}}
	evs := diff("/w", prev, cur)
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Kind != corev1.EventKind_EVENT_KIND_FILE_CREATED {
		t.Errorf("want CREATED, got %v", evs[0].Kind)
	}
	if got := evs[0].GetFilesystem().GetResolvedPath(); got != filepath.Join("/w", "b.txt") {
		t.Errorf("path = %q", got)
	}
}

func TestDiffDetectsModifyBySize(t *testing.T) {
	prev := snapshot{"a.txt": {size: 1, modNano: 5}}
	cur := snapshot{"a.txt": {size: 9, modNano: 5}}
	evs := diff("/w", prev, cur)
	if len(evs) != 1 || evs[0].Kind != corev1.EventKind_EVENT_KIND_FILE_MODIFIED {
		t.Fatalf("want one MODIFIED, got %+v", evs)
	}
}

// Isolates the modtime guard: same size, only modtime advances → still MODIFIED.
// A size-only implementation would miss this.
func TestDiffDetectsModifyByModtimeOnly(t *testing.T) {
	prev := snapshot{"a.txt": {size: 1, modNano: 5}}
	cur := snapshot{"a.txt": {size: 1, modNano: 6}}
	evs := diff("/w", prev, cur)
	if len(evs) != 1 || evs[0].Kind != corev1.EventKind_EVENT_KIND_FILE_MODIFIED {
		t.Fatalf("want one MODIFIED for a same-size modtime change, got %+v", evs)
	}
}

func TestDiffUnchangedProducesNothing(t *testing.T) {
	prev := snapshot{"a.txt": {size: 1, modNano: 5}}
	cur := snapshot{"a.txt": {size: 1, modNano: 5}}
	if evs := diff("/w", prev, cur); len(evs) != 0 {
		t.Fatalf("unchanged should produce no events, got %+v", evs)
	}
}

func TestDiffDeletedProducesNothing(t *testing.T) {
	prev := snapshot{"a.txt": {size: 1, modNano: 5}}
	cur := snapshot{}
	if evs := diff("/w", prev, cur); len(evs) != 0 {
		t.Fatalf("a removed file should produce no event (create/modify only), got %+v", evs)
	}
}

func TestToEventCarriesPathNoContent(t *testing.T) {
	ev := toEvent("/watched", "secret.txt", corev1.EventKind_EVENT_KIND_FILE_CREATED)
	if got := ev.GetFilesystem().GetResolvedPath(); got != filepath.Join("/watched", "secret.txt") {
		t.Errorf("resolved path = %q", got)
	}
	if ev.ConnectorId != "filewatch" {
		t.Errorf("connector id = %q", ev.ConnectorId)
	}
	// FilesystemSubject carries a path only — there is structurally no content field.
}

// --- watcher I/O (real temp dir, Linux-proven) ---

func mustOpen(t *testing.T, dir string, opts ...Option) *Watcher {
	t.Helper()
	w, err := Open(dir, opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A pre-existing file must NOT fire — the baseline is primed silently. If priming
// were broken, the first scan-diff would emit it and Next would return it instead
// of the context timeout.
func TestWatcherSilentPriming(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "old.txt"), "x")
	w := mustOpen(t, dir, WithInterval(10*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	ev, err := w.Next(ctx)
	if err == nil {
		t.Fatalf("priming broken: got an event for a pre-existing file: %s",
			ev.GetFilesystem().GetResolvedPath())
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestWatcherDetectsCreateAfterStart(t *testing.T) {
	dir := t.TempDir()
	w := mustOpen(t, dir, WithInterval(10*time.Millisecond))

	write(t, filepath.Join(dir, "new.txt"), "hello")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.Kind != corev1.EventKind_EVENT_KIND_FILE_CREATED {
		t.Errorf("want CREATED, got %v", ev.Kind)
	}
	if got := ev.GetFilesystem().GetResolvedPath(); got != filepath.Join(dir, "new.txt") {
		t.Errorf("path = %q", got)
	}
}

func TestWatcherDetectsModify(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	write(t, p, "12345")
	w := mustOpen(t, dir, WithInterval(10*time.Millisecond))

	write(t, p, "1234567890") // size change → MODIFIED regardless of modtime granularity
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.Kind != corev1.EventKind_EVENT_KIND_FILE_MODIFIED {
		t.Errorf("want MODIFIED, got %v", ev.Kind)
	}
}

// Several changes in one scan are returned one Event per Next call, in sorted order.
func TestWatcherOneEventPerNext(t *testing.T) {
	dir := t.TempDir()
	w := mustOpen(t, dir, WithInterval(10*time.Millisecond))

	write(t, filepath.Join(dir, "a.txt"), "1")
	write(t, filepath.Join(dir, "b.txt"), "2")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev1, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	ev2, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	if ev1.GetFilesystem().GetResolvedPath() != filepath.Join(dir, "a.txt") ||
		ev2.GetFilesystem().GetResolvedPath() != filepath.Join(dir, "b.txt") {
		t.Errorf("want a.txt then b.txt, got %s then %s",
			ev1.GetFilesystem().GetResolvedPath(), ev2.GetFilesystem().GetResolvedPath())
	}
}

func TestWatcherContextCancelReturns(t *testing.T) {
	dir := t.TempDir()
	w := mustOpen(t, dir, WithInterval(time.Hour)) // long interval so Next is parked

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := w.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// Exceeding the tracked-file cap is counted, never silently dropped.
func TestWatcherOverflowCounted(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"1", "2", "3", "4", "5"} {
		write(t, filepath.Join(dir, n+".txt"), "x")
	}
	w := mustOpen(t, dir, WithCap(2), WithInterval(10*time.Millisecond))
	if got := w.Overflow(); got != 3 {
		t.Fatalf("overflow = %d, want 3 (5 files, cap 2)", got)
	}
}
