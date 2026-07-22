## Context

The classifier runs a fixed set of `Detector`s (`Type()` + `Scan(text) → count, confidence`). EDM is a
detector too, but a *configured* one: it needs the operator's fingerprint index. So it is added to the
classifier only when an index is loaded, and the index is a k-anonymized bloom filter that can be
serialized and shipped into the sandboxed worker without carrying the raw dataset (ADR-9).

## Goals / Non-Goals

**Goals**
- A bloom-filter `EDMIndex` (build from values, add, contains) with a bounded, computable FP rate; no
  external dependency.
- Serialize/load the index (bloom bits + params) — never the raw values.
- An index builder that normalizes values and skips low-entropy/short tokens.
- An `edm` detector: tokenize content, normalize, count index hits; a new `DETECTOR_TYPE_EDM`.
- Prove: indexed values hit; non-indexed distinctive values miss (within FP); low-entropy skipped; the
  serialized index round-trips and carries no raw value.

**Non-Goals**
- Multi-cell record correlation (the FP-reducing follow-up).
- IDM / OCR (separate DLP-3 follow-ups).
- Index signing (ADR-9 tamper-evidence) — the k-anonymized index is safe to ship unsigned; signing is a
  noted follow-up.

## Decisions

### D1 — Bloom filter, k-anonymized by construction
The index stores only fingerprints (SHA-256 of normalized values) in a bloom filter — never the raw
values or their full hashes. This is what lets the index ship into the sandboxed worker (or an endpoint)
without the sensitive dataset leaving the operator (D10/D11, ADR-9). The bloom's size is chosen for a
target false-positive rate at the dataset size, and the achieved FP rate is a computable function of
(m, k, n) — so the capability's FP is *measured*, not hand-waved. A standard double-hashing scheme
(two 32-bit halves of one SHA-256) gives the k probe positions without k separate hashes.

### D2 — Normalize so a value matches across formatting
An account number written `1234-5678` in the dataset and `1234 5678` in a flow is the same value.
Normalization lowercases and strips non-alphanumerics before hashing, so EDM matches the value, not its
punctuation. The same normalization is applied at index-build and at scan time.

### D3 — Skip low-entropy tokens at index time
A dataset column of first names would index `john`, and every flow mentioning John would "match" — a
useless flood. The builder skips tokens below a minimum length and purely-short-alphabetic common
shapes, indexing only distinctive values (the identifiers EDM exists to protect). This is the primary FP
control in this single-value increment; multi-cell correlation is the stronger follow-up. What was
skipped is reported (a count), never silently dropped.

### D4 — EDM is its own detector type
A format hit (`DETECTOR_TYPE_CREDIT_CARD`) and an exact-data hit (`DETECTOR_TYPE_EDM`) mean different
things — the latter is *this specific record*, a stronger signal an operator will route differently
(block vs. alert). So EDM reports `DETECTOR_TYPE_EDM`, not `CUSTOM`, keeping the closed enum meaningful.
Its confidence reflects the bloom FP rate (high but not 1.0 — a bloom hit is probabilistic).

## Risks / Trade-offs

- **Single-value FP** — a bloom hit can be a false positive, and a coincidental real-but-not-indexed
  value can hit; bounded by the FP rate and the low-entropy skip, with multi-cell correlation the real
  fix. Stated in the proposal and D3.
- **Static index** — rebuilt when the dataset changes; the file-load model matches the other feeds.

## Migration Plan

Additive: one proto enum value (regenerated), a new file in `internal/classify`, an optional detector
added only when an index is configured, worker load wiring. The default classifier is unchanged.

## Open Questions

- Whether the scan-time tokenizer should also consider multi-word spans (for values containing spaces).
  Deferred with multi-cell correlation.
