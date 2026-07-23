package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// fimWatchDirs returns the deduped set of directories to watch for real-time FIM: a file path resolves
// to its parent directory, a directory path to itself. The watch is on directories (with child events),
// so a change to a file surfaces as an event on its directory — robust across delete+recreate of the
// file (an inode mark on the file itself would be lost).
func fimWatchDirs(paths []string) []string {
	set := map[string]struct{}{}
	for _, p := range paths {
		d := p
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			d = filepath.Dir(p)
		}
		set[d] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// runFimTriggerLoop is the portable core: on each trigger it debounces (coalescing a burst), re-scans
// the baseline, and emits any drift — the fanotify event is only the trigger; fim.Scan is the detector,
// so a timestomped edit is caught and a change that does not alter content yields no drift.
func runFimTriggerLoop(ctx context.Context, m *fim.Manifest, paths []string, opts fim.Options, debounce time.Duration, trigger <-chan struct{}, events chan<- *corev1.Event, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			settle(ctx, trigger, debounce)
			drifts, _, err := fim.Scan(m, paths, opts)
			if err != nil {
				log.Error("fim: real-time re-scan failed", slog.String("err", err.Error()))
				continue
			}
			for _, d := range drifts {
				select {
				case events <- fimEvent(d):
					log.Warn("fim: integrity drift (real-time)", slog.String("path", d.Path), slog.String("change", string(d.Change)))
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// settle waits up to d for the trigger stream to go quiet, draining triggers that arrive during the
// window so a burst of change events coalesces into one scan.
func settle(ctx context.Context, trigger <-chan struct{}, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		case <-timer.C:
			return
		}
	}
}
