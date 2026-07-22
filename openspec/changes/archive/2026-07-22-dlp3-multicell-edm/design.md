## Context

Single-value EDM uses a bloom filter — membership only, no per-value structure, so it cannot tell which
record a matched value belongs to. Multi-cell correlation needs exactly that structure: a mapping from a
cell fingerprint to the records that contain it, so the scanner can group hits by record and apply a
threshold.

## Goals / Non-Goals

**Goals**
- A `RecordIndex`: `cellFingerprint → []recordID`, `recordID → distinctCellCount`, a match threshold.
- `BuildRecordIndex(records, threshold)` skipping low-entropy cells and records too small to reach the
  threshold.
- A record-EDM detector: per-record distinct-cell tally, match at threshold; serialize/load; worker wiring.
- Prove the multi-cell precision (≥threshold same-record cells hits; one cell, or cross-record cells, miss).

**Non-Goals**
- Proximity (cells must be near each other) — a refinement.
- IDM / OCR (the remaining DLP-3 pieces).
- Perfect k-anonymity against brute-force of low-entropy fields (a known EDM/D193 limitation).

## Decisions

### D1 — A fingerprint→records map, not a bloom, so hits group by record
Each record's distinctive cells are fingerprinted (a 64-bit truncation of SHA-256 over the normalized
cell). The index maps `fingerprint → recordIDs`, and `recordID → distinctCellCount`. On scan, each content
token's fingerprint yields the records it could belong to; per record we accumulate the SET of distinct
cell fingerprints seen, and a record whose distinct-cell count reaches the threshold is a match. The map
holds only hashes and integer ids — no raw values (ADR-9).

### D2 — Threshold is the precision knob; records too small to reach it are not indexed
A record matches only when `threshold` distinct cells of it appear (default 2 — two specific fields of
one record co-occurring is already strong, low-FP evidence). A record with fewer than `threshold`
distinctive cells can never match, so `BuildRecordIndex` skips it and reports the skipped count (never a
silent drop — the operator sees which records were too generic to protect this way).

### D3 — Low-entropy cells are skipped; the brute-force limitation is stated
As in single-value EDM, cells below the distinctiveness bar are not indexed (they would both over-match
and be trivially brute-forceable from their hash). The index stores hashes, not raw values, which
prevents casual disclosure; a determined attacker with the index can still brute-force a low-entropy
field's hash — the same known limitation as the single-value bloom (D193), carried forward and stated,
not newly introduced. Multi-cell matching is what buys the precision the single hash cannot.

### D4 — Composes with single-value EDM; reports the same detector type
Record EDM is another detector added to the classifier, reporting `DETECTOR_TYPE_EDM` (an exact-data
match, whether single-value or record-level — the policy routes on the type; the confidence distinguishes
strength). An operator can run either or both indexes.

## Risks / Trade-offs

- **No proximity** — cells co-occurring anywhere in a large document match even if unrelated in the text;
  still far more precise than single-value, and proximity is the noted refinement.
- **Fingerprint collisions** — a 64-bit truncation collides at ~D²/2⁶⁴ (negligible for realistic D), and
  the ≥threshold-distinct-cells requirement compounds independent collisions to astronomically unlikely.

## Migration Plan

Additive: new types + a detector in `internal/classify`, worker wiring. No proto change (reuses
`DETECTOR_TYPE_EDM`). The default classifier and single-value EDM are unchanged.

## Open Questions

- Whether to add token proximity (a sliding window over the content) so cells must be near each other.
  Deferred; anywhere-in-content is already strong and simpler.
