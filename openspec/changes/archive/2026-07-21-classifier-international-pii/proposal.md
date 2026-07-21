## Why

The classifier covered Brazilian (CPF) and US (SSN, card) PII plus secrets, but not
international financial PII or health data. Phase D2 completes the detector set with IBAN
(a mod-97-checksummed, strong, low-FP detector like CPF) and a conservative health-data
dictionary detector (no checksum exists, so it is capped low and requires multiple terms).

## What Changes

- `internal/classify/international.go`: `iban` (ISO 7064 mod-97-10 + per-country fixed
  length; handles the space-grouped printed form) and `healthData` (a small high-signal
  dictionary requiring ≥3 distinct terms, low confidence). New DetectorType enum values
  IBAN/HEALTH_DATA.

## Capabilities

### Modified Capabilities
- `pattern-classifier`: adds international financial (IBAN) and health-data detectors.

## Impact

- `proto/…/classification.proto` (+2 enum values, regenerated); new
  `internal/classify/international.go`; `docs/decisions.md` D98.
- Proven: real mod-97-valid IBANs (DE/GB/FR, including the space-grouped form and a
  letter-bearing BBAN) detected; a wrong-check-digit, a wrong-length (including a string
  that PASSES mod-97 but is the wrong length for its country), and an unknown country
  read clean; multi-term health text fires at low confidence, a single term does not.
  Guards mutation-tested (mod-97-bypassed; country-length-dropped; health-threshold-weakened).
- NOT in scope (stated): passport numbers (country-specific formats, weak validators);
  exhaustive IBAN country coverage (a representative subset — an unknown code is rejected,
  not silently admitted); health-term dictionary tuning / localization. Health data has NO
  checksum, so — like SSN/email — its confidence is capped and it is corroborating evidence,
  not a strong standalone hit.
