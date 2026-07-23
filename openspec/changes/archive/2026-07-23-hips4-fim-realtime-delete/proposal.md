# Real-time FIM deletion detection (HIPS-4 / FIM increment 4)

## Why
FIM's real-time watch (D228) triggers an immediate integrity re-scan on a file MODIFICATION
(`FAN_MODIFY | FAN_CLOSE_WRITE`), so a tampered file is caught in milliseconds. But a **deletion** — the
"remove the evidence" tamper, and a first-class FIM signal since D223 (`EVENT_KIND_FILE_DELETED`) — is not
in the watch mask, so it is only caught by the periodic poll, up to one interval late. An attacker who
deletes a critical file (a log, a binary, a config) has that whole window before the alert fires. Closing
it is the stated D228 deferral: *"real-time delete (`FAN_DELETE`, poll-caught now)."*

## What Changes
- Add `FAN_DELETE | FAN_MOVED_FROM` to the real-time watch mask so a child deleted from (or moved out of) a
  watched directory fires the same immediate re-scan that a modification does. `fim.Scan` already reports
  the deletion as `DELETED` drift → `EVENT_KIND_FILE_DELETED`; the only missing piece is the trigger.
- No change to the detector, the event, or the poll (which stays the completeness backstop). The fanotify
  event remains only a trigger — `fim.Scan` decides what actually drifted.

The genuinely kernel-gated question is whether the existing **unprivileged** FID-reporting watch
(`FAN_REPORT_DFID_NAME`) actually delivers `FAN_DELETE` on a directory mark; this is verified on the rooted
test VM (kernel 6.8). If a deletion fires the trigger and produces a `FILE_DELETED` event in ~ms, the gap is
closed; if the kernel requires more, that is a real finding to record.

## Impact
- Affected capability: `file-integrity-monitoring` (ADDED requirement — real-time deletion detection).
- Affected code: `cmd/openshield-engine/fimwatch_linux.go` (mask + comment).
- No proto change (the `FILE_DELETED` kind already exists), no migration, no new dependency.
- **Deferred (stated):** `FAN_MOVED_TO`/`FAN_CREATE` real-time (an ADD is a weaker tamper signal and still
  poll-caught); per-file inode marks; a privileged mount-wide watch; non-Linux.
