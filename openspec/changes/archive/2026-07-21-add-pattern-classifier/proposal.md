# Add the pattern classifier (T-007)

## Why

The agent's process boundary (T-006) exists and carries a `Classifier` interface, but the only
implementation is a test fake. Nothing yet turns bytes into detector hits, so the walking
skeleton has no classification stage and T-008 (policy) has no input to evaluate.

This change implements the endpoint classifier: format-plus-checksum detection for the PII
types the schema names, running in the unprivileged worker, emitting **type + confidence +
count only**.

## What changes

**A `Classifier` implementation in a new `internal/classify` package**, wired into the worker.
It runs a set of detectors over the bounded byte stream the worker already provides and returns
`[]*corev1.DetectorHit`.

**Detectors are format match plus a validator, not format alone:**
- **CPF** (Brazil): 11 digits with the two check digits verified. Check digits are what
  separate a real CPF from any 11-digit string.
- **Credit card**: 13–19 digits passing the Luhn checksum.
- **SSN** (US): 9 digits passing the structural rules the SSA publishes (area not 000/666/
  900–999, group not 00, serial not 0000). SSN has **no checksum** — this is stated as a known
  weakness, not hidden, because it means SSN confidence is inherently lower than CPF or card.
- **Email**: format only. No validator exists; confidence is correspondingly low.

**Confidence reflects the strength of the evidence (D4), and is never 1.0.** A Luhn-valid card
is still sometimes a Luhn-valid non-card; a structurally-valid SSN is a weak signal. Policy
consumes these as thresholds, not booleans.

**The detector engine is RE2 (Go's `regexp`), chosen for its linear-time guarantee.** A
backtracking engine is a ReDoS primitive: classification runs on attacker-influenced content,
and a pattern that can be made to run for seconds is a fail-open bypass (D17) — make
classification slow and every Block becomes an Allow. RE2 cannot be driven to catastrophic
backtracking, so this is a security property, not a style preference.

## What this does NOT claim or cover

- **No NER, no ML, no spaCy/Presidio** (D5). Endpoint classification is patterns and checksums
  only. Person names, addresses and other NER-shaped entities are out of scope by decision, not
  omission — the NER path is not endpoint-viable and its precision (~22.7% on names) would make
  every policy that consumed it noise.
- **No content leaves the classifier.** `DetectorHit` carries type, confidence and count — no
  matched text, no offset, no hash, no fingerprint (D10, D11). The matched text exists only
  inside the worker, in `LocalClassification`, and the two-type split (T-003) makes sending it
  a compile error rather than a discipline.
- **No reversible digest of low-entropy PII.** Emitting a hash of a CPF or SSN would be
  emitting the CPF or SSN — the search space is brute-forceable (D10). The count is not a
  digest: it reveals how many matched, not what they were.
- **Not a completeness claim.** Format+checksum detection misses PII that is encoded, split
  across a boundary beyond the read window, or in a format no detector models. The honest
  claim is "detects these specific patterns in readable text", not "finds all PII".
- **It does not decide anything.** The classifier emits evidence; Policy (T-008) decides. An
  enforcer never sees the classifier, its regexes or its confidences — only the Decision (D14).

## Decisions

Depends on **D5** (patterns and deny-lists only), **D10** (type + confidence + count; no
content, no reversible hash of low-entropy PII), **D11** (no fingerprints/embeddings), **D4**
(confidence, not certainty), **D14** (enforcers see only the Decision), and the T-006 process
boundary.

Establishes a small new decision: **the detector engine MUST be a linear-time (RE2-class)
matcher**, because classification runs on attacker-influenced bytes and a backtracking engine
is a denial-of-service and fail-open primitive.
