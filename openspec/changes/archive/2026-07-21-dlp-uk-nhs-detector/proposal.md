# DLP: UK NHS number detector

## Why

UK healthcare deployments handle NHS numbers — the 10-digit patient identifier — and an NHS
number in a document is strong evidence of health-context data. The classifier had no NHS
detector, and an NHS number carries a weighted mod-11 check digit, fitting the checksum discipline.

## What Changes

- **`DETECTOR_TYPE_UK_NHS` enum value** (16), additive.
- **A `ukNHS` detector**: the conventional 3-3-4 SPACE-separated grouping validated by the NHS
  weighted mod-11 check digit. Space (not hyphen) grouping is deliberate — it is the canonical
  presentation and avoids overlap with the hyphen/dot phone format. Confidence 0.85.

This adds to the `pattern-classifier` capability.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `proto/openshield/v1/classification.proto` (+ regenerated `corev1`),
  `internal/classify/detectors.go`, `classify.go`.
- Not in scope (stated): the bare/hyphenated NHS forms (FP-prone / phone-overlapping); the
  age/format variations of legacy numbers; other national health identifiers.
