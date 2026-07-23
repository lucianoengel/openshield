## Context

The engine (`cmd/openshield-engine`) runs multiple event sources — fanotify `watch`, `execSource`, a
DNS source — each a goroutine pushing `*corev1.Event` into a shared `events` channel that a consumer
drains into `eng.Process` (Event → Classify → Policy → Decision → Audit). `filewatch` snapshots by
size+mtime and drops deletions; `classifyStage` classifies a filesystem event by opening its
`resolved_path` in the worker. FIM adds a persistent cryptographic baseline and a producer that emits
drift events into that same channel.

## Goals / Non-Goals

**Goals:**
- Detect drift of critical files from a persistent known-good baseline: **modify** (content hash
  differs, even with mtime+size preserved), **add**, **delete**.
- Make each drift an auditable pipeline decision (a policy can ALERT).
- No root; bounded; deterministic.

**Non-Goals (deferred, stated in the spec):** real-time inotify/fanotify watch (privileged/perf),
remediation/rollback, xattr/ACL/ownership/permission monitoring, recursive include/exclude globs, a
**signed** tamper-evident manifest, Windows/macOS path sets.

## Decisions

1. **Cryptographic baseline is the differentiator.** The manifest stores `sha256` (+ size, as a cheap
   pre-filter and for reporting). `Scan` recomputes the hash and reports `modified` on any hash
   difference — so a timestomped edit (mtime+size restored) is still caught, which the mtime+size
   `filewatch` misses. This is the property the killer test and mutation guard exercise.

2. **Deletion is first-class → one additive event kind.** `EVENT_KIND_FILE_DELETED = 10`. A baseline
   path absent at scan time is a `deleted` drift. Modify/add reuse `FILE_MODIFIED`/`FILE_CREATED`.

3. **A deleted-file event is metadata-only in the engine.** `classifyStage` currently opens a filesystem
   event's `resolved_path`; a deleted file cannot be opened, so the worker would error and the drift
   would never reach the policy. Fix: `classifyStage` treats a `FILE_DELETED` event like the existing
   metadata-only branch — an empty `LocalClassification`, proceed to policy. This is correct in general
   (a deleted file has no content), not a FIM special case. A `FILE_MODIFIED` drift (file still present)
   classifies by path normally; if it also contains sensitive content, that is an additive bonus signal.

4. **Producer mirrors `execSource`.** `fimSource` holds a manifest + the watched paths, and on a ticker
   runs `Scan`, emitting one content-free Event per drift (carrying `FilesystemSubject.resolved_path`,
   never content, D10). A send races `ctx.Done()` so shutdown never blocks. Startup builds+saves the
   baseline on first run (no manifest file yet) and loads it thereafter.

5. **Manifest shape.** `Manifest{ Entries map[string]Entry }`, `Entry{ SHA256 string; Size int64 }`,
   JSON on disk. `BuildBaseline(paths, opts)` walks the paths (a file → itself; a directory →
   non-recursive regular files in increment 1, matching `filewatch`'s scope), hashing each under the
   size cap. `Scan(manifest, paths)` rebuilds the current view the same way and diffs: a path in the
   baseline but not current = deleted; current but not baseline = added; both but hash differs =
   modified; equal = no drift.

6. **Bounded and honest.** `maxHashBytes` caps per-file hashing; an oversized file is recorded as an
   explicit "oversized" entry (flagged), never silently omitted (a silent skip would read as "verified,
   unchanged"). A `maxPaths` cap bounds the walk; overflow is surfaced (logged), like `filewatch`'s
   overflow.

## Risks / Trade-offs

- **The manifest is unsigned (increment 1).** An attacker with write access to `OPENSHIELD_FIM_BASELINE`
  can rewrite it to hide drift. This is called out loudly in the spec and the startup log; a signed
  manifest is the named next increment. FIM still raises the bar (an attacker must now also find and
  rewrite the baseline), and the manifest can be placed on read-only/again-monitored storage.
- **Poll, not real-time.** Drift is detected on the next scan, not instantly; a file changed and
  reverted between scans is missed. Accepted for increment 1 (the compliance/tamper baseline question is
  the value); real-time watch is the deferred privileged optimization.
- **Non-recursive directory scan** matches `filewatch` and bounds cost; recursive globs are deferred.
- **TOCTOU on modify→classify:** a modified file may change again before the worker opens it; this is the
  same TOCTOU the fanotify path already lives with, and the drift Event is already emitted regardless.
