## Context

Record-EDM (D197) matches when cells of a record co-occur; IDM is the same shape one level up: instead of
a record's cells, a document's *shingles* (overlapping word k-grams), and instead of a fixed cell count,
a *fraction* of the document's shingles. Both use a fingerprint→ids map and a per-id threshold; IDM
differs in the unit (shingle) and the threshold (fraction of the document).

## Goals / Non-Goals

**Goals**
- `DocumentIndex`: `shingleFingerprint → []docID`, `docID → shingleCount`, `k`, `matchFraction`.
- `shingle(text, k)` — normalized overlapping word k-grams.
- `BuildDocumentIndex(docs, k, fraction)`; an IDM detector (per-doc distinct-shingle tally, fire at the
  fraction); serialize/load; worker wiring; a distinct `DETECTOR_TYPE_IDM`.
- Prove excerpt/reformat tolerance and the fraction threshold.

**Non-Goals**
- Winnowing / min-hash shingle selection (a scale refinement).
- OCR (needs an engine dependency).
- Cross-document dedup of shared shingles (boilerplate) — a refinement.

## Decisions

### D1 — Word k-gram shingles, normalized, so excerpts and reformats still match
A document is shingled into overlapping windows of `k` consecutive normalized words (lowercase, runs of
non-alphanumeric collapsed to a single boundary). k-grams make the match robust to reformatting
(whitespace, punctuation, casing) and to excerpting — an excerpt that contains a run of `k` words in
order produces the same shingle fingerprints as the original. `k=5` by default: long enough that a
shingle is high-entropy (so its hash is not brute-forceable and boilerplate rarely collides), short
enough that a modest excerpt still yields several shingles.

### D2 — Fire on a FRACTION of the document's shingles, not an absolute count
A document match means "a substantial portion of this document is present." So the detector fires when a
document's distinct matched shingles reach `ceil(matchFraction × its shingle count)` — scale-invariant
across document sizes. Default `0.3`: a third of a document present is a strong exfiltration signal while
tolerating that an excerpt is not the whole thing. A document too short to produce enough shingles for
the fraction is still indexable (the fraction of a small count is small), but a single-shingle document
is skipped (nothing to fingerprint meaningfully) and counted.

### D3 — A distinct DETECTOR_TYPE_IDM
A document match is a different signal from a structured-data (EDM) match and a policy may route it
differently (a leaked contract vs a leaked account number), so IDM reports its own `DETECTOR_TYPE_IDM`
rather than reusing EDM's — keeping the closed enum meaningful (the same reasoning as D192's separate
threat type and D193's separate EDM type).

### D4 — Same map + per-id-threshold shape as record-EDM; hashes only
The index is `shingleFingerprint(uint64) → docIDs` plus `docID → shingleCount`, holding only hashes and
ids — no raw document text (ADR-9, k-anonymized). Scanning shingles the content the same way and tallies
per-document distinct shingle fingerprints, mirroring record-EDM's per-record grouping (so two documents'
shingles never combine).

## Risks / Trade-offs

- **Index size for large corpora** — all shingles stored; winnowing bounds it and is the noted follow-up.
  For moderate document sets this is fine.
- **Shared boilerplate** — a common header shingled into many documents inflates matches; the fraction
  threshold and k-gram width mitigate, and boilerplate stripping is a refinement.

## Migration Plan

Additive: one proto enum value (regenerated), new types + a detector in `internal/classify`, worker
wiring. The default classifier, EDM, and record-EDM are unchanged.

## Open Questions

- Whether to winnow (min-hash) shingles now for scale. Deferred; full-shingle is simpler and correct for
  moderate corpora.
