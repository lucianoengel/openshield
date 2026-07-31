package main

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/meminject"
)

// memInjectEvent builds a content-free memory-injection event: the pid + executable path only, NEVER the
// process's memory contents. The engine classifies it metadata-only.
func memInjectEvent(pid int, exe string) *corev1.Event {
	return &corev1.Event{
		Kind:        corev1.EventKind_EVENT_KIND_MEMORY_INJECTION_SUSPECTED,
		EventId:     "meminject-" + exe + "-" + strconv.Itoa(pid),
		ConnectorId: "memscan",
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid:      int32(pid),
			ExecPath: exe,
		}},
	}
}

// memScanSource is the memory-injection producer (HIPS-4): on a poll it scans running processes for
// writable+executable memory (the W^X-violation injection signature) and emits ONE high-severity event
// per NEW suspect (keyed by pid+exec-path, so a standing suspect does not re-fire every poll). It logs
// how many processes it could not read — a hint that a fleet-wide scan needs more privilege (root).
func memScanSource(ctx context.Context, procRoot string, interval time.Duration, jit meminject.JITAllowlist, events chan<- *corev1.Event, log *slog.Logger) {
	seen := map[string]bool{}
	var suppressed int
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			suspects, unreadable := meminject.ScanAll(procRoot)
			if unreadable > 0 {
				log.Debug("meminject: some processes were unreadable (scan runs unprivileged over own processes; root scans the fleet)", slog.Int("unreadable", unreadable))
			}
			// AN EXEMPTION IS A REDUCTION IN COVERAGE AND IS SAID OUT LOUD. A scanner that quietly
			// explained away half the machine reads exactly like a quiet machine (D31/D419).
			if suppressed > 0 {
				log.Info("meminject: W+X processes explained by the JIT allowlist (their ANONYMOUS regions only; a file-backed W+X mapping is still reported)", slog.Int("explained", suppressed))
				suppressed = 0
			}
			for pid, regions := range suspects {
				exe := meminject.ExePath(procRoot, pid)
				// HIPS-4 inc 2: a JIT writes instructions into memory and runs them, which by permission
				// bits alone is what shellcode does. Without this the browser is reported on every scan
				// and the operator turns the detector off. Only ANONYMOUS regions of a listed, still-
				// present executable are explained — a file-backed W+X mapping survives the exemption,
				// because browsers are the most-targeted injection host and an allowlist that covered
				// everything would be a permanent blind spot exactly there.
				if len(jit.Unexplained(exe, regions)) == 0 {
					suppressed++
					continue
				}
				key := strconv.Itoa(pid) + "|" + exe
				if seen[key] {
					continue
				}
				seen[key] = true
				select {
				case events <- memInjectEvent(pid, exe):
					log.Warn("meminject: SUSPECTED CODE INJECTION — writable+executable memory", slog.Int("pid", pid), slog.String("exe", exe))
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
