## 1. Proto (additive)

- [x] 1.1 `proto/openshield/v1/event.proto`: add `EVENT_KIND_FILE_DELETED = 10` to `EventKind`.
- [x] 1.2 `make proto`; `git add internal/core/corev1/*.pb.go` BEFORE `proto-check`.

## 2. The FIM engine (`internal/fim`)

- [x] 2.1 Types: `Entry{SHA256 string, Size int64, Oversized bool}`, `Manifest{Entries map[string]Entry}`, `Drift{Path string, Change Change}` with `Change` ∈ modified/added/deleted, `Options{MaxHashBytes int64, MaxPaths int}`.
- [x] 2.2 `BuildBaseline(paths []string, opts) (*Manifest, overflow int, err error)`: expand each path (a file → itself; a directory → non-recursive regular files, like `filewatch.scan`), hash each under `MaxHashBytes` (oversized → `Oversized:true`, still recorded), cap the total at `MaxPaths` (overflow surfaced).
- [x] 2.3 `Scan(m *Manifest, paths, opts) ([]Drift, overflow int, err error)`: rebuild the current view the same way, diff vs `m`: baseline∖current = deleted; current∖baseline = added; both with differing hash = modified; equal = none. Deterministic (sorted).
- [x] 2.4 `SaveManifest(path)/LoadManifest(path)` (JSON); round-trips the hashes.
- [x] 2.5 `hashFile(path, max)` via `crypto/sha256` + a bounded reader; an oversized file is flagged, never silently skipped.

## 3. FIM producer

- [x] 3.1 `cmd/openshield-engine/fimsource.go`: `fimSource(ctx, m *fim.Manifest, paths []string, interval, opts, events chan<- *corev1.Event, log)` — on a ticker, `Scan`, and emit one Event per drift (modified→FILE_MODIFIED, added→FILE_CREATED, deleted→FILE_DELETED) carrying `FilesystemSubject.resolved_path`; a send races `ctx.Done()`. Content-free.

## 4. Engine classify fix

- [x] 4.1 `internal/engine/engine.go` `classifyStage.Run`: a `FILE_DELETED` event is metadata-only — hand it an empty `LocalClassification` and `Continue` (do NOT open the missing path), exactly like the non-file branch. A `FILE_MODIFIED`/`FILE_CREATED` event still classifies by path.

## 5. Wiring

- [x] 5.1 `cmd/openshield-engine/main.go`: behind `OPENSHIELD_FIM_PATHS` (comma-separated) + `OPENSHIELD_FIM_BASELINE`: if the baseline file is absent, `BuildBaseline` + `SaveManifest` (first-run capture) with a loud "baseline captured — REVIEW it" log; else `LoadManifest`. Start `fimSource` on `OPENSHIELD_FIM_INTERVAL` (default e.g. 60s). Loud warn + inert when `OPENSHIELD_FIM_PATHS` unset. Log the unsigned-manifest limitation loudly.

## 6. Tests (real files in t.TempDir, real engine→policy path, no seeded literals)

- [x] 6.1 `TestScanDetectsTimestompedModification` (KILLER): build a baseline, rewrite a file's content to the SAME length and restore its original mtime via `os.Chtimes` → `Scan` reports modified (the hash caught what size+mtime cannot).
- [x] 6.2 `TestScanDetectsDeletion` / `TestScanDetectsAddition` / `TestScanCleanNoDrift`.
- [x] 6.3 `TestManifestRoundTrip`: `SaveManifest`→`LoadManifest` preserves hashes; a scan against the loaded manifest matches.
- [x] 6.4 `TestOversizedFileFlaggedNotSkipped`: a file over `MaxHashBytes` is recorded `Oversized`, the build/scan completes.
- [x] 6.5 `TestFimDriftAlertsThroughEngine` (end-to-end): a real engine (real worker) + a policy that ALERTs on FILE_MODIFIED/DELETED for the watched path; drive `fimSource` (or Scan→emit) with a modified then deleted file → the pipeline produces an ALERT decision for each, and the DELETE does NOT error in classify (proves task 4.1).

## 7. Mutation verification

- [x] 7.1 Mutation — `Scan` compares only size+mtime (ignore the hash): `TestScanDetectsTimestompedModification` FAILs. Revert.
- [x] 7.2 Mutation — drop deletion detection (never emit `deleted`): `TestScanDetectsDeletion` (and the e2e delete alert) FAILs. Revert.
- [x] 7.3 Mutation — `classifyStage` opens a FILE_DELETED path (remove the metadata-only branch): the e2e delete-alert test FAILs (classify errors, no alert). Revert.

## 8. Gate & land

- [x] 8.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (test in background; `git checkout -- openshield-*` after any build; `proto-check` clean).
- [x] 8.2 decisions.md D-entry; the new capability spec is authored under `openspec/specs/file-integrity-monitoring/` at sync; run doccheck (`go test ./internal/doccheck/`).
- [x] 8.3 Update the roadmap: HIPS-4 FIM increment 1 DONE; archive the change; commit, `git pull --rebase`, push.
