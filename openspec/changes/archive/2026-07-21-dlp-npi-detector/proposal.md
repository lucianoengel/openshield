# DLP: US National Provider Identifier (NPI) detector

## Why

Healthcare deployments handle NPIs — the 10-digit identifier for every US healthcare provider —
and an NPI in a document is a strong signal of health-context data. The classifier had no NPI
detector, and an NPI carries a real Luhn check digit, so it fits the checksum discipline.

## What Changes

- **`DETECTOR_TYPE_NPI` enum value** (15), additive.
- **An `npi` detector**: a bare 10-digit candidate validated by BOTH the leading-digit rule
  (every NPI begins with 1 or 2) AND the Luhn checksum over the `80840`-prefixed number (the
  published NPI check). Both are required — the prefix constraint eliminates most non-NPI
  10-digit runs the checksum alone would pass. Confidence 0.80 (a real check-digit scheme, a
  touch below the card Luhn because a bare 10-digit run is common and collides with phone numbers).

This adds to the `pattern-classifier` capability.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `proto/openshield/v1/classification.proto` (+ regenerated `corev1`),
  `internal/classify/detectors.go`, `classify.go`.
- Not in scope (stated): distinguishing individual (type-1) from organizational (type-2) NPIs by
  the leading digit (both are PHI-adjacent); the taxonomy/enumeration-date enrichment; other
  national provider schemes.
