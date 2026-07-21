## Context

`worker.Classifier` is `Classify(ctx, io.Reader) ([]*corev1.DetectorHit, error)`. The worker
opens the file with its own unprivileged credentials, applies a byte ceiling (`limitReader`),
and hands the bounded stream to the classifier. Everything in this change lives behind that
interface, in the unprivileged worker, where parsing attacker-controlled bytes is the whole
point of the process split.

The output type `DetectorHit` is already `{DetectorType, confidence, count}` — no field can
carry content. That constraint is upstream of this change and this change must not widen it.

## Goals / Non-Goals

**Goals:**
- Detect CPF, credit card, SSN and email in readable text, with confidence that reflects
  whether a checksum backed the match.
- Emit only type + confidence + count, proven by a test that greps the serialized output for
  the seeded PII values.
- Use a linear-time matcher so classification cannot be turned into a fail-open bypass.

**Non-Goals:**
- NER, ML, fuzzy matching, or any second-order detector (entropy, dictionaries) — later phases
  if ever.
- Streaming match across arbitrary boundaries. The worker's ceiling bounds input; the
  classifier reads that bounded stream fully. A match split across the ceiling is a miss, and
  that miss is the honest limit of a bounded read, recorded not hidden.
- Deciding, alerting, or enforcing. Evidence only.

## Decisions

### One `Detector` interface, a fixed registry
```go
type Detector interface {
    Type() corev1.DetectorType
    // Scan returns the number of VALID matches and the confidence to report.
    Scan(text []byte) (count int, confidence float64)
}
```
The classifier runs every registered detector and emits one `DetectorHit` per detector that
found ≥1 match. A detector that finds nothing emits nothing — an absent hit and a
zero-confidence hit are different, and the summary should carry only what was actually found.

### Candidate regex (RE2) then a validator
Each detector pairs a broad candidate pattern with a checker:
- **CPF**: `\d{3}\.?\d{3}\.?\d{3}-?\d{2}`, strip formatting, verify both check digits mod 11.
  Reject the all-same-digit sequences (`000...`, `111...`) that pass the arithmetic but are
  documented invalids.
- **Credit card**: `\d(?:[ -]?\d){12,18}`, strip separators, Luhn. Length 13–19.
- **SSN**: `\d{3}-\d{2}-\d{4}` (the hyphenated form; bare 9-digit runs collide with too much to
  be worth the false positives), structural validation only. Confidence capped low to say so.
- **Email**: a single RFC-pragmatic pattern, format only.

Confidence, fixed and documented, never 1.0:
- CPF check-digit valid: **0.95**
- Card Luhn valid: **0.90**
- SSN structurally valid: **0.60** (no checksum exists; this is a weak signal by construction)
- Email format valid: **0.50**

These are deliberately conservative. A classifier that reports 0.99 for a Luhn match invites a
policy author to treat it as certainty, which D4 exists to prevent.

### Count is distinct valid matches, de-duplicated
The same CPF appearing five times is signal about repetition, but for a first classifier the
honest and simple count is the number of matches that passed validation. De-duplication of
identical normalized values within one document, so a repeated test fixture does not inflate
the count, is done on a normalized-value set held ONLY for the duration of the scan and never
emitted.

### Reading the stream
`io.ReadAll` on the worker-bounded reader. The ceiling is already enforced upstream; reading
the whole bounded slice keeps matching simple and correct (no boundary-spanning bugs) at a
memory cost the ceiling already caps. If a future detector needs true streaming, that is its
change to make, with its own justification.

## Risks / Trade-offs

- **False positives are inherent.** A Luhn-valid 16-digit number in a CSV of order IDs is a
  card as far as this detector knows. The mitigation is confidence < 1 and Policy thresholds,
  not a cleverer regex — and the dogfood ticket (T-015) measures the real FP rate.
- **The bounded read is a real miss surface.** PII past the ceiling is not seen. The worker
  already reports `truncated`; a policy can treat a truncated scan as lower-assurance. This
  change does not paper over it.
- **De-dup-by-value holds normalized PII in memory during the scan.** That is inside the
  worker, the one place matched content is legitimately present (it already holds the raw
  bytes). Nothing derived from it is emitted. The set is dropped when Scan returns.
- **SSN without a checksum is weak.** Reported honestly via a 0.60 cap rather than dropped —
  a weak signal a policy can choose to use is more honest than pretending SSN detection is as
  strong as CPF.
