## Why

Single-value EDM (D193) flags any content token that matches a fingerprinted value — useful, but a single
identifier can appear by coincidence, and low-entropy fields over-match. Enterprise EDM's precision comes
from **record correlation**: only fire when *several cells of the same record* co-occur — a name AND its
SSN AND its account number together. Coincidentally matching multiple specific fields of one record is
astronomically unlikely, so multi-cell EDM has a far lower false-positive rate. This completes the core
of DLP-3 EDM: the enterprise-grade, record-level match.

## What Changes

- A record-structured EDM index: for each sensitive record (a row of cells), store per-record cell
  fingerprints (hashes only, no raw values), so the scanner can tell *which record* a matched cell
  belongs to and require a threshold of distinct cells of the SAME record.
- A record-EDM detector: tokenize content, fingerprint candidate values, tally distinct cell hits per
  record, and report a match only when a record reaches its cell threshold — reported as
  `DETECTOR_TYPE_EDM` at high confidence (a multi-cell record match is near-definitive).
- Serialization (ship the index into the sandbox, ADR-9) and worker wiring, composing with the
  single-value EDM and the built-in detectors.

## Capabilities

### New Capabilities
<!-- none — extends exact-data-matching -->

### Modified Capabilities
- `exact-data-matching`: adds record-level (multi-cell) matching — a match requires a threshold of
  distinct cells of the same record to co-occur, the low-false-positive enterprise EDM mode.

## Impact

- **Code:** `internal/classify` gains a `RecordIndex` (per-record cell fingerprints), a record-EDM
  detector, serialize/load, and `Classifier.AddRecordEDM`; the worker loads a record index from an env.
  Proven: content with ≥threshold cells of one record matches; content with only ONE cell of a record
  does NOT (the multi-cell precision — lower FP than single-value); one cell each from TWO different
  records does NOT match (no single record reaches threshold); the serialized index carries no raw value.
- **Scope note (honest):** a record matches when its cells co-occur anywhere in the content;
  **proximity** (the cells must be near each other) is a refinement, noted. The index stores cell hashes,
  not raw values — like the single-value bloom (D193), a determined attacker with the index can still
  brute-force LOW-ENTROPY fields, which is why low-entropy cells are skipped; this is a known EDM
  limitation carried forward, stated. **IDM** (document fingerprinting) and **OCR** are the remaining
  DLP-3 pieces.
