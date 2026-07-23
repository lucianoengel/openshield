## 1. The canary engine (`internal/canary`)

- [x] 1.1 `Plant(dir string, n int) ([]string, error)` — write n decoy files (plausible names/content) into dir if absent (idempotent); return their paths. `Entropy(b []byte) float64` — Shannon entropy over bytes (0..8).
- [x] 1.2 `Detector{Threshold int, Window time.Duration}` + `Observe(canaryPath string, at time.Time) bool` — record the change; return true when the count of DISTINCT canary paths changed within `[at-Window, at]` reaches `Threshold`. Prune entries older than the window. Concurrency-safe.

## 2. Proto + engine

- [x] 2.1 `proto/openshield/v1/event.proto`: `EVENT_KIND_RANSOMWARE_SUSPECTED = 11`. `make proto`; stage the pb.go before `proto-check`.
- [x] 2.2 `internal/engine/engine.go` `classifyStage.Run`: a `EVENT_KIND_RANSOMWARE_SUSPECTED` event is metadata-only (empty classification → policy), like `FILE_DELETED` — do not open the affected path.

## 3. Producer + wiring (`cmd/openshield-engine`)

- [x] 3.1 (POLL-based, not fanotify — encrypted canaries stay changed so a scan sees the whole mass-change at once; real-time via the shared FIM watch is a noted enhancement) `canarySource(ctx, baseline, canaryDirs/paths, detector, opts, events, log)` — reuse the fanotify watch (fim real-time pattern) to trigger a `fim.Scan` of the canaries on a change; for each drifted (modified/deleted) canary call `detector.Observe`; on a detection emit ONE `EVENT_KIND_RANSOMWARE_SUSPECTED` event (subject = the affected dir; confidence raised when a modified canary is high-entropy). Debounced/coalesced.
- [x] 3.2 `cmd/openshield-engine/main.go`: behind `OPENSHIELD_CANARY_DIRS` (+ `OPENSHIELD_CANARY_COUNT`, `_THRESHOLD`, `_WINDOW`): `canary.Plant` each dir, build the canary `fim.Manifest`, start `canarySource`. Loud log; inert when unset.

## 4. Tests

- [x] 4.1 `TestDetectorFiresOnThreshold` (no root): Threshold distinct canaries within the window → fires; a single change → no fire; the same canary repeated → no fire (distinct count); changes older than the window pruned → no fire.
- [x] 4.2 `TestEntropy`: random bytes → ≈8; repeated byte → 0; text → mid.
- [x] 4.3 `TestPlantIdempotent`: Plant writes n files; a second Plant does not overwrite (baseline stable).
- [x] 4.4 `TestRansomwareAlertsThroughEngine` (real engine + worker, gated on fanotify if via the watch, or drive Scan→Observe→emit directly): mass-modify planted canaries → a `RANSOMWARE_SUSPECTED` event → a policy that alerts on the kind → ALERT decision, and classify does NOT open the affected files.

## 5. Mutation verification

- [x] 5.1 Mutation — `Detector.Observe` counts total changes (not DISTINCT paths): `TestDetectorFiresOnThreshold`'s same-canary-repeated case FAILs (it now false-fires). Revert.
- [x] 5.2 Mutation — `Observe` does not prune old entries: the spread-out-changes case FAILs (accumulates). Revert.
- [x] 5.3 Mutation — `classifyStage` opens a RANSOMWARE event's path: the engine alert test FAILs (worker errors on an encrypted/missing file). Revert.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `proto-check` clean; cross-compile clean.
- [x] 6.2 decisions.md D-entry; author the new capability spec under `openspec/specs/ransomware-canary/`; doccheck.
- [x] 6.3 Update the roadmap: HIPS-4 ransomware canary DONE — correlated mass-change detection + entropy, pipeline-alerting. Archive; commit; `git pull --rebase`; push.
