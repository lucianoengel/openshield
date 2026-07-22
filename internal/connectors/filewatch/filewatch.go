// Package filewatch is a PORTABLE, unprivileged file-observation connector.
//
// It is the cross-platform analogue of the Linux fanotify connector (D52): the
// endpoint engine opens it on operating systems where fanotify does not exist
// (windows, darwin) so the SAME agent runs and observes there instead of exiting.
// It reuses the existing FilesystemSubject Event and the existing FILE_CREATED /
// FILE_MODIFIED kinds — a new PRODUCER, not a core change (D26).
//
// Mechanism: pure standard-library polling. Each interval it scans the watched
// directory (os.ReadDir + file metadata) and diffs the snapshot against the
// previous one; a new path is a creation, a changed size-or-modtime is a
// modification. Pure stdlib means the identical code compiles AND runs on every
// GOOS, so the detection logic is proven on Linux and needs no privilege or code
// signing. It produces PATHS, never content (D29); classification stays in the
// worker. It is observe-only (D1) and takes no action on any file.
//
// Coverage is honest, not adversary-proof (threat model: the careless insider):
// a poll interval misses sub-interval churn, and it is non-recursive. Native OS
// watch APIs (ReadDirectoryChangesW / FSEvents) are a later optimization on this
// same Open/Next/Close seam.
package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

const (
	defaultInterval = 2 * time.Second
	defaultCap      = 10000
)

// fileState is the metadata the diff compares. Content is never read (D29).
type fileState struct {
	size    int64
	modNano int64
}

// snapshot maps a file name (not full path) to its observed state.
type snapshot map[string]fileState

// toEvent builds a content-free FilesystemSubject Event for a change, exactly as
// the fanotify connector does — resolved path only, no matched text.
func toEvent(dir, name string, kind corev1.EventKind) *corev1.Event {
	return &corev1.Event{
		ConnectorId: "filewatch",
		Kind:        kind,
		EventId:     "fw-" + name,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{
				ResolvedPath: filepath.Join(dir, name),
			}}},
	}
}

// diff is the PURE detection core: it compares two snapshots and returns one Event
// per change. A name present now but not before is a creation; a name whose size or
// modification time changed is a modification; unchanged and removed names produce
// nothing. Names are walked in sorted order so the output is deterministic (a
// removed file simply never appears — no delete Event, matching the fanotify
// connector's create/modify mapping).
func diff(dir string, prev, cur snapshot) []*corev1.Event {
	names := make([]string, 0, len(cur))
	for n := range cur {
		names = append(names, n)
	}
	sort.Strings(names)

	var evs []*corev1.Event
	for _, n := range names {
		c := cur[n]
		p, existed := prev[n]
		switch {
		case !existed:
			evs = append(evs, toEvent(dir, n, corev1.EventKind_EVENT_KIND_FILE_CREATED))
		case c.size != p.size || c.modNano != p.modNano:
			evs = append(evs, toEvent(dir, n, corev1.EventKind_EVENT_KIND_FILE_MODIFIED))
		}
	}
	return evs
}

// scan reads the watched directory (regular files only, non-recursive) into a
// snapshot. It tracks at most cap files; the number beyond the cap is returned as
// overflow so the caller can surface it LOUDLY — silent truncation would
// misrepresent coverage. os.ReadDir returns entries sorted by name, so which files
// fall past the cap is stable across scans (no spurious create/modify churn).
func scan(dir string, cap int) (snapshot, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	snap := make(snapshot, len(entries))
	overflow := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// Vanished between ReadDir and Info, or unreadable — skip, not fatal.
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if len(snap) >= cap {
			overflow++
			continue
		}
		snap[e.Name()] = fileState{size: info.Size(), modNano: info.ModTime().UnixNano()}
	}
	return snap, overflow, nil
}

// Option configures a Watcher.
type Option func(*Watcher)

// WithInterval sets the poll interval (default 2s). Tests use a small value.
func WithInterval(d time.Duration) Option { return func(w *Watcher) { w.interval = d } }

// WithCap sets the maximum number of files tracked per scan (default 10000).
func WithCap(n int) Option { return func(w *Watcher) { w.cap = n } }

// Watcher observes a directory by polling. It exposes the same Open/Next/Close
// shape as the fanotify connector so the engine consumes it through one interface.
type Watcher struct {
	dir      string
	interval time.Duration
	cap      int
	last     snapshot
	pending  []*corev1.Event
	overflow atomic.Int64
}

// Open validates dir, takes a SILENT baseline snapshot (so pre-existing files do
// not flood the pipeline at startup), and returns a ready watcher.
func Open(dir string, opts ...Option) (*Watcher, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("filewatch: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("filewatch: %s is not a directory", dir)
	}
	w := &Watcher{dir: dir, interval: defaultInterval, cap: defaultCap}
	for _, o := range opts {
		o(w)
	}
	base, ov, err := scan(dir, w.cap)
	if err != nil {
		return nil, fmt.Errorf("filewatch: initial scan of %s: %w", dir, err)
	}
	w.last = base
	if ov > 0 {
		w.overflow.Add(int64(ov))
	}
	return w, nil
}

// Next blocks until the next file change is available (or ctx is done) and returns
// one Event. Changes from a single scan are buffered and returned one per call,
// matching the fanotify watcher's one-event-per-Next contract.
func (w *Watcher) Next(ctx context.Context) (*corev1.Event, error) {
	for {
		if len(w.pending) > 0 {
			ev := w.pending[0]
			w.pending = w.pending[1:]
			return ev, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(w.interval):
		}
		cur, ov, err := scan(w.dir, w.cap)
		if err != nil {
			return nil, err
		}
		if ov > 0 {
			w.overflow.Add(int64(ov))
		}
		w.pending = diff(w.dir, w.last, cur)
		w.last = cur
	}
}

// Close releases the watcher. Polling holds no OS handle, so this is a no-op that
// exists to satisfy the same interface as the fanotify watcher.
func (w *Watcher) Close() error { return nil }

// Overflow reports how many files have been dropped past the tracked-file cap since
// Open. A non-zero value means the watched directory is larger than the cap and
// coverage is partial — surfaced, never silent.
func (w *Watcher) Overflow() int64 { return w.overflow.Load() }
