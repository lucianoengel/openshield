# Tasks

## 1. Proto
- [x] 1.1 Add `DETECTOR_TYPE_IDM = 19` to `proto/openshield/v1/classification.proto`. `make proto`;
  commit generated `corev1`.

## 2. Document index + detector
- [x] 2.1 `internal/classify/idm.go`: `shingle(text, k) []uint64` — lowercase, split on runs of
  non-alphanumeric, form overlapping k-word windows, fingerprint each (SHA-256[:8]). `DocumentIndex`
  (`shingles map[uint64][]uint32`, `docShingles map[uint32]int`, `k int`, `matchFraction float64`).
- [x] 2.2 `BuildDocumentIndex(docs []string, k int, fraction float64)` — shingle each doc, map
  fingerprint→docID, store distinct-shingle count; SKIP a doc with < 2 distinct shingles and count it.
- [x] 2.3 An IDM detector (`Type()==DETECTOR_TYPE_IDM`): shingle content, per-doc accumulate the SET of
  distinct shingle fingerprints, fire when a doc reaches `ceil(fraction × its shingle count)`; confidence
  scales with the matched fraction (capped < 1.0). `AddIDM(index)` / `NewWithIDM(index)`.
- [x] 2.4 `Marshal()`/`LoadDocumentIndex(bytes)` — hashes + ids + counts + k + fraction, never raw text.

## 3. Worker wiring
- [x] 3.1 The worker loads a serialized document index from `OPENSHIELD_IDM_INDEX` (when set) and
  `AddIDM`s it; a malformed index aborts startup.

## 4. Tests
- [x] 4.1 Build a document index (k=5, fraction 0.3) from a couple of documents; a REFORMATTED EXCERPT
  covering ≥30% of a doc's shingles → an IDM match; a tiny snippet (a few shingles, below the fraction) →
  NO match; unrelated text → NO match; two docs' shingles never combine.
- [x] 4.2 A single-shingle document is skipped (skipped count reported) and never matches.
- [x] 4.3 Serialize round-trip matches the same documents AND the bytes contain none of the raw text.
- [x] 4.4 Detector integration: `NewWithIDM(index).Classify(excerpt)` reports `DETECTOR_TYPE_IDM`; the
  default classifier does not.

## 5. Mutation guards
- [x] 5.1 Make the detector fire at 1 matched shingle (ignore the fraction threshold) → the
  below-fraction-snippet test (4.1) FAILs. Revert.
- [x] 5.2 Make the detector tally shingles across ALL docs (not per doc) → the two-docs-don't-combine
  case (4.1) FAILs. Revert.

## 6. Record + close
- [x] 6.1 `docs/decisions.md`: new entry (D198) — IDM document fingerprinting; k-gram shingles;
  fraction threshold; k-anonymized index; winnowing/OCR follow-ups; distinct DETECTOR_TYPE_IDM.
- [x] 6.2 `docs/architecture-roadmap.md`: note DLP-3 IDM shipped; OCR remains (dep-gated).
- [x] 6.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync the delta into
  `openspec/specs/document-fingerprinting/spec.md`.
