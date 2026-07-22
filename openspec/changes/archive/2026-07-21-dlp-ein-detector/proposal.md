# DLP: US Employer Identification Number (EIN) detector

## Why

EINs — the 9-digit US tax id for businesses, written NN-NNNNNNN — appear in W-9s, invoices, and
HR/finance documents. The classifier detected personal tax ids (SSN) but not the employer one.
An EIN has no checksum, but its two-digit prefix must be an IRS-assigned campus code, a published
whitelist that serves as a structural validator.

## What Changes

- **`DETECTOR_TYPE_EIN` enum value** (17), additive.
- **An `ein` detector**: the conventional `NN-NNNNNNN` grouping (distinct from the SSN 3-2-4
  shape) validated by the IRS campus-prefix whitelist on the first two digits. Confidence 0.60 —
  structural only, on par with SSN (no checksum).

This adds to the `pattern-classifier` capability.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `proto/openshield/v1/classification.proto` (+ regenerated `corev1`),
  `internal/classify/detectors.go`, `classify.go`.
- Not in scope (stated): the bare (unhyphenated) EIN form (collides with SSN-without-hyphens and
  other 9-digit runs); distinguishing EIN from ITIN/ATIN (different number spaces); validating the
  serial portion (the IRS publishes no serial checksum).
