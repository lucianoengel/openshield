package main

import (
	"context"
	"log/slog"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// fimSource is the File Integrity Monitoring producer (HIPS-4): on a ticker it rescans the watched
// critical paths against the known-good baseline and emits one content-free Event per drift into the
// engine's event channel — modified→FILE_MODIFIED, added→FILE_CREATED, deleted→FILE_DELETED — so a
// tamper finding flows the pipeline to the policy and is audited. The baseline is fixed for the process
// lifetime (an operator re-captures it deliberately); the event carries the path only, never content
// (D10). A send races ctx cancellation so shutdown never blocks.
func fimSource(ctx context.Context, m *fim.Manifest, paths []string, interval time.Duration, opts fim.Options, events chan<- *corev1.Event, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			drifts, overflow, err := fim.Scan(m, paths, opts)
			if err != nil {
				log.Error("fim: scan failed", slog.String("err", err.Error()))
				continue
			}
			if overflow > 0 {
				log.Warn("fim: path cap exceeded — coverage is incomplete", slog.Int("skipped", overflow))
			}
			for _, d := range drifts {
				ev := fimEvent(d)
				select {
				case events <- ev:
					log.Warn("fim: integrity drift", slog.String("path", d.Path), slog.String("change", string(d.Change)))
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// fimEvent builds a content-free FilesystemSubject Event for a drift.
func fimEvent(d fim.Drift) *corev1.Event {
	var kind corev1.EventKind
	switch d.Change {
	case fim.Added:
		kind = corev1.EventKind_EVENT_KIND_FILE_CREATED
	case fim.Deleted:
		kind = corev1.EventKind_EVENT_KIND_FILE_DELETED
	default:
		kind = corev1.EventKind_EVENT_KIND_FILE_MODIFIED
	}
	return &corev1.Event{
		Kind:    kind,
		EventId: "fim-" + string(d.Change) + "-" + d.Path,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: d.Path},
		}},
	}
}
