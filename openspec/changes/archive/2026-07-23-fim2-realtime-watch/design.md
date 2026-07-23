## Context

The FIM poll source (`fimSource`, D223) runs `fim.Scan(baseline, paths)` on a ticker and emits drift
events via `fimEvent`. The fanotify connector (`internal/connectors/fanotify`) provides an unprivileged
NOTIFY watch of a directory (`Open(dir)` / `Next(ctx)` — FILE_CREATED/MODIFIED), build-tagged linux with
a portable stub. Real-time FIM couples the two: a fanotify event triggers a `fim.Scan` immediately.

## Goals / Non-Goals

**Goals:** detect a change to a watched critical file in ~milliseconds by triggering a baseline re-check
on a fanotify event; keep the poll as a backstop; best-effort (fail-to-wire).

**Non-Goals:** real-time deletion via `FAN_DELETE` (poll-caught in inc 1); an inotify fallback; per-file
marks; making real-time the sole detector.

## Decisions

1. **The fanotify event is the trigger; the baseline scan is the detector.** On a change event, run the
   SAME `fim.Scan` the poll runs — so a modification detected in real time still goes through the
   cryptographic hash comparison (a timestomped edit is caught, a benign metadata touch that doesn't
   change content yields no drift). The fanotify event only says "look now," never decides drift itself.

2. **Debounce a burst into one scan.** A file save often emits several events (open/modify/close); a
   `cp`/editor over a directory emits many. After a trigger, wait a short quiet window (`debounce`,
   e.g. 200ms) draining further triggers, then scan once. This bounds scan work under churn while keeping
   latency low.

3. **Watch the containing directories, deduped.** A FIM path may be a file or a directory; the fanotify
   connector watches a directory. `fimWatchSource` computes the set of directories to watch (a file →
   its parent, a directory → itself), de-duplicates, and opens one watcher per directory, fanning their
   events into a single trigger channel. Reuses `fim.Scan(baseline, fimPaths)` for the actual check.

4. **The poll stays; real-time is additive.** `fimWatchSource` runs alongside `fimSource`. fanotify can
   drop events on overflow and does not report every deletion; the poll (D223) remains the completeness
   guarantee. Real-time only lowers latency for the common modify/create case.

5. **Fail-to-wire.** If a directory's fanotify watch cannot open (a restricted sandbox, a missing dir),
   log it and continue with whatever watches did open (and the poll). A real-time watch that can't arm
   never stops FIM — it degrades to poll-only.

## Risks / Trade-offs

- **fanotify can miss events (queue overflow); it does not report deletion for a dir NOTIFY mark.** The
  poll backstop covers both — real-time is a latency optimization, not a coverage guarantee. Stated.
- **Scan-on-event under heavy churn** could be costly; the debounce coalesces bursts, and the scan is the
  same bounded operation the poll already runs.
- **Per-directory granularity** means an event on any file in a watched dir triggers a full `fim.Scan` of
  the FIM set — acceptable for the low-churn critical-file dirs FIM targets; per-file marks are a
  refinement.
- **Availability varies** (containers/sandboxes may restrict fanotify). The gated test skips where it is
  unavailable; production degrades to poll-only with a loud log.
