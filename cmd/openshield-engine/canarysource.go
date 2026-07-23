package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/canary"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// canaryCheck is the ransomware-detection core (HIPS-4): it re-scans the canary baseline, feeds each
// drifted (modified/deleted) canary to the correlation detector, and reports whether the mass-change
// threshold fired plus the highest content entropy seen among the still-present drifted canaries (the
// encryption signature, used to raise the emitted event's confidence). It is pure over the filesystem +
// detector, so the ransomware logic is unit-testable without a producer loop.
func canaryCheck(m *fim.Manifest, paths []string, det *canary.Detector, at time.Time, opts fim.Options) (fired bool, maxEntropy float64) {
	drifts, _, err := fim.Scan(m, paths, opts)
	if err != nil {
		return false, 0
	}
	for _, d := range drifts {
		if det.Observe(d.Path, at) {
			fired = true
		}
		if d.Change == fim.Modified {
			if b, err := os.ReadFile(d.Path); err == nil {
				if e := canary.Entropy(b); e > maxEntropy {
					maxEntropy = e
				}
			}
		}
	}
	return fired, maxEntropy
}

// canaryEvent builds a content-free ransomware event for the affected directory. The affected files may
// be encrypted or deleted, so only the location crosses (D10) — the engine classifies it metadata-only.
func canaryEvent(dir string, confidence float64) *corev1.Event {
	_ = confidence // confidence is carried on the Decision by the policy; the event stays content-free
	return &corev1.Event{
		Kind:    corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED,
		EventId: "ransomware-" + dir,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: dir},
		}},
	}
}

// canarySource is the ransomware canary producer (HIPS-4): on a ticker it re-checks the planted canaries
// against their baseline and, when a threshold of them change within the window (canaryCheck fires),
// emits ONE high-severity ransomware event into the pipeline (then resets the detector so a persistent
// encrypted state does not re-fire every tick). A poll is sufficient — encrypted canaries stay changed,
// so a scan sees the whole mass-change at once. (Real-time triggering by sharing the FIM fanotify watch
// is a noted enhancement; the correlated-mass-change detection is identical either way.)
func canarySource(ctx context.Context, m *fim.Manifest, dir string, paths []string, det *canary.Detector, interval time.Duration, events chan<- *corev1.Event, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			fired, ent := canaryCheck(m, paths, det, now, fim.Options{})
			if !fired {
				continue
			}
			conf := 0.7
			if ent >= 7.5 { // high-entropy content among the changed canaries = encryption
				conf = 0.95
			}
			select {
			case events <- canaryEvent(dir, conf):
				log.Warn("canary: SUSPECTED RANSOMWARE — mass canary change", slog.String("dir", dir), slog.Float64("max_entropy", ent))
			case <-ctx.Done():
				return
			}
			det.Reset() // avoid re-firing every tick while the canaries stay changed
		}
	}
}
