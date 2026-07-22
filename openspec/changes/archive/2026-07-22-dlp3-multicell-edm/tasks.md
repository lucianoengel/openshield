# Tasks

## 1. Record index + detector
- [x] 1.1 `internal/classify/edm_record.go`: `RecordIndex` (`cells map[uint64][]uint32` fingerprint→record
  ids, `recordCells map[uint32]int` id→distinct-cell count, `threshold int`); `cellFingerprint(value)`
  = first 8 bytes of SHA-256 over `normalizeEDM(value)`; `BuildRecordIndex(records [][]string, threshold)`
  — per record collect distinctive cells (reuse `distinctiveEDM`), fingerprint each, map fingerprint→id,
  record the id's distinct-cell count; SKIP a record with `< threshold` distinctive cells and count it.
- [x] 1.2 A record-EDM detector (`Type()==DETECTOR_TYPE_EDM`): tokenize with the same adjacent-token
  windows, fingerprint each window, accumulate per-record the SET of distinct cell fingerprints hit, and
  count records reaching `threshold`; confidence high (near-1.0, capped < 1.0). `AddRecordEDM(index)`.
- [x] 1.3 `Marshal()`/`LoadRecordIndex(bytes)` — serialize the maps + threshold (only hashes + ids +
  counts, never raw values).

## 2. Worker wiring
- [x] 2.1 The worker loads a serialized record index from `OPENSHIELD_EDM_RECORD_INDEX` (when set) and
  `AddRecordEDM`s it; a malformed index aborts startup.

## 3. Tests
- [x] 3.1 Build a record index (threshold 2) from a few multi-cell records; content with ≥2 distinct
  cells of one record (across formatting) → an EDM match; content with only ONE cell of a record → NO
  match; one cell each from TWO different records → NO match (the multi-cell precision).
- [x] 3.2 A record with fewer than `threshold` distinctive cells is skipped (skipped count reported) and
  never matches.
- [x] 3.3 Serialize round-trip matches the same records AND the bytes contain none of the raw values.
- [x] 3.4 Detector integration: `NewWithRecordEDM(index).Classify(content)` reports `DETECTOR_TYPE_EDM`
  for a multi-cell hit; the default classifier does not.

## 4. Mutation guards
- [x] 4.1 Make the detector match at 1 cell (ignore the threshold) → the single-cell-no-match test (3.1)
  FAILs. Revert.
- [x] 4.2 Make the detector tally cell hits across ALL records (not per record) → the cross-record test
  (3.1) FAILs (two unrelated cells combine into a false match). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D197) — multi-cell record EDM; fingerprint→records map;
  threshold precision; low-entropy skip + brute-force limitation stated; proximity/IDM/OCR follow-ups.
- [x] 5.2 `docs/architecture-roadmap.md`: note DLP-3 EDM record-level shipped; IDM/OCR remain.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/exact-data-matching/spec.md`.
