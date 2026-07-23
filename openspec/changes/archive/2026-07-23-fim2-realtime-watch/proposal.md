## Why

FIM (D223) detects tampering of critical files by re-hashing them against a known-good baseline on a
**periodic poll** — so a tamper is caught up to one poll interval late (default 60s). An attacker who
edits a config or replaces a binary has that whole window before detection. This increment adds
**real-time** detection: an unprivileged fanotify NOTIFY watch on the critical paths triggers an
**immediate** baseline re-check the moment a watched file changes, so tamper is caught in milliseconds,
not on the next scan. The periodic poll stays as a backstop.

## What Changes

- **A real-time FIM source** — a fanotify NOTIFY watch (unprivileged, D52) on the directories holding the
  critical paths; on a file-change event it triggers a **debounced** `fim.Scan` against the baseline and
  emits any drift (modify-by-hash / added / deleted) into the pipeline immediately. Reuses the D223 FIM
  engine and the existing fanotify connector — the fanotify event is only the *trigger*; the drift is
  still computed by the cryptographic baseline scan (so a timestomped edit is still caught).
- **The poll remains the backstop.** fanotify can miss events under queue overflow and does not report
  every deletion; the periodic poll (D223) still runs and catches anything the real-time watch missed —
  real-time is an additive latency improvement, never the sole detector.
- **Fail-to-wire, not fail-closed.** If the fanotify watch cannot be opened (a restricted sandbox), FIM
  logs and continues with the poll alone — real-time is best-effort.
- **Opt-in** behind `OPENSHIELD_FIM_REALTIME`, alongside the existing FIM configuration.

## Capabilities

### New Capabilities
<!-- none — extends the file-integrity-monitoring capability. -->

### Modified Capabilities
- `file-integrity-monitoring`: add real-time drift detection — a change to a watched critical file
  triggers an immediate baseline re-check and drift event, in addition to the periodic scan, so tamper is
  detected without waiting for the poll interval.

## Impact

- **Code:** new `cmd/openshield-engine/fimwatch.go` (`fimWatchSource` — fanotify watch → debounce →
  `fim.Scan` → emit, reusing `fimEvent`); wiring in `main.go` behind `OPENSHIELD_FIM_REALTIME`. No proto,
  no migration, no new dependency (the fanotify connector + `fim` engine already exist).
- **Testing:** a gated test (`requireFanotify` — skip if unprivileged fanotify is unavailable) builds a
  baseline, starts the real-time source, modifies a watched file, and asserts a drift event arrives well
  within the poll interval (real-time). Runs locally (unprivileged fanotify works) and on the VM.
- **Deferred:** real-time deletion via `FAN_DELETE` marks (increment 1 catches deletes on the poll
  backstop); inotify fallback where fanotify is unavailable; per-file (not per-dir) marks.
