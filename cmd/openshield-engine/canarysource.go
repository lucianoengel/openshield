package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/canary"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// maxSuspects bounds how many processes one detection names.
//
// A bound rather than everything, because a detection that names forty processes has told an operator
// nothing they can act on — and the ranking already puts the process holding the most of the tree open
// first, which is what separates something encrypting a directory from an editor with one file in it.
const maxSuspects = 5

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
		Kind:        corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED,
		EventId:     "ransomware-" + dir,
		ConnectorId: "canary",
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: dir},
		}},
	}
}

// suspectEvents turns an attribution into one PROCESS-targeted ransomware event per suspect (HIPS-8).
//
// A SEPARATE EVENT PER SUSPECT rather than a list on the directory event, and no proto change: the
// Event target is a oneof, so an event is about a directory or about a process and cannot be both. That
// is the right shape here anyway — a policy that decides to kill decides about ONE process, and each
// decision wants its own audit row naming the process it was about.
//
// The event ids share the directory event's prefix so a timeline joins them without a correlation rule.
// The start-time rides along because a kill decided now must be able to revalidate the pid at
// enforcement time and spare a recycled one (HIPS-7).
func suspectEvents(dir string, att canary.Attribution) []*corev1.Event {
	out := make([]*corev1.Event, 0, len(att.Suspects))
	for _, s := range att.Suspects {
		out = append(out, &corev1.Event{
			Kind:        corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED,
			EventId:     fmt.Sprintf("ransomware-%s-pid%d", dir, s.PID),
			ConnectorId: "canary-attribution",
			Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
				Pid:        int32(s.PID),
				ExecPath:   s.Exe,
				StartTicks: s.StartTicks,
			}},
		})
	}
	return out
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
			// HIPS-8: ATTRIBUTE BEFORE EMITTING, and before the reset, because the encrypting process
			// is most likely still walking the tree at exactly this moment. Every second spent
			// elsewhere first is a second in which it can finish and exit, taking the only evidence of
			// which process it was with it.
			att := canary.Attribute(dir, maxSuspects)
			select {
			case events <- canaryEvent(dir, conf):
				log.Warn("canary: SUSPECTED RANSOMWARE — mass canary change", slog.String("dir", dir),
					slog.Float64("max_entropy", ent), slog.Int("suspects", len(att.Suspects)))
			case <-ctx.Done():
				return
			}
			// A BLIND ATTRIBUTION IS REPORTED AS BLIND. An unprivileged agent can read only its own
			// processes' descriptor tables, so it finds nothing every time — and an operator reading
			// "no suspects" would be told the machine is fine by a component that never got to look.
			if att.Blind() {
				log.Warn("canary: could not attribute the ransomware detection to any process — this is "+
					"NOT 'no process was responsible'. Reading another process's open files needs the "+
					"same user or CAP_SYS_PTRACE.",
					slog.String("dir", dir), slog.Int("scanned", att.Scanned),
					slog.Int("unreadable", att.Unreadable), slog.Bool("supported", att.Supported))
			}
			for _, ev := range suspectEvents(dir, att) {
				p := ev.GetProcess()
				select {
				case events <- ev:
					log.Warn("canary: RANSOMWARE SUSPECT", slog.String("dir", dir),
						slog.Int("pid", int(p.GetPid())), slog.String("exe", p.GetExecPath()))
				case <-ctx.Done():
					return
				}
			}
			det.Reset() // avoid re-firing every tick while the canaries stay changed
		}
	}
}
