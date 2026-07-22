# DLP: US bank routing number (ABA) detector

## Why

The classifier detects international bank accounts (IBAN, mod-97 checksum) but not US bank
routing numbers, a common DLP target in North-American deployments. A routing number has a real
weighted checksum, so it fits the format-plus-checksum discipline of the strongest detectors
rather than the checksumless structural rules — but the type did not exist.

## What Changes

- **A new `DETECTOR_TYPE_ABA_ROUTING` enum value** (13) — an additive extension of the detector
  enum, consistent with how it grew across phases (phone=5, iban=10, custom=12).
- **An `abaRouting` detector** in `internal/classify`: a bare 9-digit candidate validated by
  BOTH the Federal Reserve leading-digit range (00–12, 21–32, 61–72, 80) AND the ABA weighted
  mod-10 checksum (`3·(d1+d4+d7) + 7·(d2+d5+d8) + (d3+d6+d9) ≡ 0`). Both are required: the
  checksum alone passes ~1 in 10 random 9-digit runs and the range alone is far too weak, so
  together they make a bare 9-digit run reportable. Confidence 0.75 — above the checksumless
  structural detectors, below the two-check-digit schemes.

This adds to the `pattern-classifier` capability. The detector runs in the unprivileged worker
like every other, emitting type + confidence + count only (no content).

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `proto/openshield/v1/classification.proto` (+ regenerated `corev1`),
  `internal/classify/detectors.go` (detector), `classify.go` (registration).
- Not in scope (stated): the account number that accompanies a routing number (no checksum, too
  FP-prone bare — like a bare SSN); non-US routing schemes; the routing-symbol-to-institution
  lookup (a policy/enrichment concern, not detection).
