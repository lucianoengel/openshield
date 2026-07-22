# Tasks

## 1. Proto
- [x] 1.1 Add `DETECTOR_TYPE_EDM = 18` to `proto/openshield/v1/classification.proto`. `make proto`;
  commit generated `corev1`.

## 2. EDM index + detector
- [x] 2.1 `internal/classify/edm.go`: `EDMIndex` (bloom filter — bit array + k, double-hash probes from
  one SHA-256); `NewEDMIndex(targetFP float64, n int)` sizes m/k; `Add(value)`; `Contains(value)`;
  `EstimatedFP()`; `normalize(v)` (lowercase + strip non-alphanumerics). `BuildEDMIndex(values, opts)`
  normalizes, skips low-entropy tokens (min length; report the skipped count), adds the rest.
- [x] 2.2 `Marshal()`/`LoadEDMIndex(bytes)` serialize the bloom bits + params (never raw values).
- [x] 2.3 An `edm` detector (`Type()==DETECTOR_TYPE_EDM`): tokenize `text` into candidate values,
  normalize each, count distinct index hits; confidence reflects `1 - EstimatedFP` (capped < 1.0).
- [x] 2.4 `classify.NewWithEDM(index)` (or a `With` option) adds the EDM detector to the default set only
  when an index is present; `New()` unchanged.

## 3. Worker wiring
- [x] 3.1 The worker loads a serialized EDM index from `OPENSHIELD_EDM_INDEX` (when set) and builds the
  classifier with EDM; unset = the default classifier (no EDM). A malformed index aborts worker startup.

## 4. Tests
- [x] 4.1 Bloom units: an added value is contained; a not-added distinctive value is not (spot-check
  across many, assert the empirical FP is within the target); `EstimatedFP` is sane for the params.
- [x] 4.2 Index build: distinctive values (account numbers, member ids) are indexed and detected in
  content across formatting (`1234-5678` indexed → `1234 5678` in text hits); low-entropy tokens (short
  common words) are skipped (the skipped count is reported).
- [x] 4.3 Serialize round-trip: `LoadEDMIndex(index.Marshal())` matches the same values, AND the
  serialized bytes contain NONE of the raw indexed values (grep the bytes).
- [x] 4.4 Detector: content with an indexed value → an EDM hit with `DETECTOR_TYPE_EDM`; content with
  only non-indexed distinctive values → no EDM hit (within FP); the default classifier (no EDM) reports
  no EDM type.

## 5. Mutation guards
- [x] 5.1 Make `Contains` ignore some probe bits (check only the first hash) → the FP-rate test (4.1)
  FAILs (FP rises far above target). Revert.
- [x] 5.2 Make `BuildEDMIndex` NOT skip low-entropy tokens → the low-entropy-skip test (4.2) FAILs.
  Revert.

## 6. Record + close
- [x] 6.1 `docs/decisions.md`: new entry (D193) — EDM exact-data-matching; k-anonymized bloom index
  (ships into the sandbox, ADR-9); measured FP; low-entropy skip; single-value now, multi-cell/IDM/OCR/
  index-signing follow-ups.
- [x] 6.2 `docs/architecture-roadmap.md`: mark DLP-3 EDM (single-value) shipped; note remaining DLP-3.
- [x] 6.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync the delta into
  `openspec/specs/exact-data-matching/spec.md`.
