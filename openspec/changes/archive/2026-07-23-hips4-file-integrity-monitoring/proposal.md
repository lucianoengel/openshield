## Why

The platform has no File Integrity Monitoring — a classic, expected endpoint control. An attacker who
modifies a critical file (an audit rule, `sshd_config`, `/etc/passwd`, an openshield binary) or deletes
one leaves no signal today. The existing `filewatch` connector is not FIM: it snapshots by size+mtime,
**ignores deletions**, and only detects "changed since I started watching" — so a modification that
**preserves mtime and size** (timestomping / `touch -r` restore, the standard tamper evasion) passes
completely unseen. FIM answers the real question — *has this file drifted from its approved known-good
state?* — with a persistent **cryptographic baseline**, and makes every drift an auditable pipeline
decision.

## What Changes

- **New `internal/fim` package** — a persistent **SHA-256 baseline manifest** (`path → {sha256, size}`).
  `BuildBaseline(paths)` hashes the critical set; `Scan(manifest, paths) → []Drift{Path, Change}` where
  `Change ∈ {modified, added, deleted}`; `Load/SaveManifest` (JSON) so the known-good baseline is
  operator-approvable and survives a restart. Bounded: a max-file-size-to-hash cap (an oversized file is
  flagged, not silently skipped) and a max path count.
- **Detects what filewatch cannot**: a content change with preserved mtime+size (caught by the hash),
  and **deletion** of a baseline file (a top tamper signal).
- **A FIM producer** — `fimSource`, a scanner goroutine (mirroring `execSource`) that periodically
  `Scan`s and emits one content-free `*corev1.Event` per drift into the engine's event channel, so a
  drift flows Event → Classify → Policy → Decision → Audit — an auditable tamper alert.
- **Proto (additive):** `EVENT_KIND_FILE_DELETED = 10` — deletion is a first-class FIM signal and no
  delete kind exists today. Modify/add reuse `FILE_MODIFIED`/`FILE_CREATED`.
- **Engine fix:** a `FILE_DELETED` event has no content to open, so `classifyStage` classifies it as
  **metadata-only** (empty classification, proceed to policy) — correct in general (a deleted file has
  no bytes) and required so a delete drift reaches the policy instead of erroring in the worker's
  `os.Open`.
- **Wiring:** behind `OPENSHIELD_FIM_PATHS` + `OPENSHIELD_FIM_BASELINE` (built+saved on first run,
  loaded thereafter) + `OPENSHIELD_FIM_INTERVAL`; inert with a loud warn when unset. **No root** —
  periodic hashing with the agent's own credentials.

## Capabilities

### New Capabilities
- `file-integrity-monitoring`: detect drift of operator-designated critical files from a persistent
  cryptographic baseline (modify via content hash, add, delete), emitting each drift as an auditable
  pipeline event a policy can alert on.

### Modified Capabilities
<!-- none — the engine classify-stage change is an internal correctness fix carried by the new
     capability's requirements, not a spec-level change to an existing capability. -->

## Impact

- **Code:** new `internal/fim/`; `cmd/openshield-engine/` (a `fimSource` + wiring); one line of behavior
  in `internal/engine/engine.go` (`classifyStage` treats a deleted-file event as metadata-only).
- **Proto:** one additive enum value (`EVENT_KIND_FILE_DELETED`); `make proto`, stage the regenerated
  `pb.go` before `proto-check`. No migration, no new dependency (`crypto/sha256`, `encoding/json`).
- **Honest limitation (stated loudly):** increment 1's manifest is a **plain file** — an attacker with
  write access to the manifest can hide drift by rewriting it. A signed/tamper-evident manifest is a
  named follow-up. Deferred too: real-time inotify/fanotify watching (privileged/perf), remediation,
  xattr/ACL/ownership monitoring, recursive include/exclude globs, and Windows/macOS path sets (PLAT-7).
