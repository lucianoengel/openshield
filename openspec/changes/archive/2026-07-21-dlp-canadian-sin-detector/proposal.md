# DLP: Canadian Social Insurance Number (SIN) detector

## Why

The classifier detects US and international financial identifiers (SSN, IBAN, ABA routing) but
not the Canadian SIN, core PII in any Canadian deployment. A SIN carries a Luhn checksum, so it
fits the format-plus-checksum discipline of the strongest detectors.

## What Changes

- **A new `DETECTOR_TYPE_CA_SIN` enum value** (14) — additive, like the other detector types.
- **A `caSIN` detector**: the conventional grouped form `NNN-NNN-NNN` (hyphen or space
  separated) validated by the Luhn checksum over its 9 digits. A BARE 9-digit run is not
  matched — like a bare SSN it collides with too much; the grouping is what makes it a SIN
  candidate and the Luhn filters the rest. Confidence 0.85 (Luhn over a distinctive grouping is
  strong, a touch below the card Luhn because the number is shorter so a chance pass is likelier).

This adds to the `pattern-classifier` capability; the detector runs in the unprivileged worker
and emits type + confidence + count only.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `proto/openshield/v1/classification.proto` (+ regenerated `corev1`),
  `internal/classify/detectors.go`, `classify.go`.
- Not in scope (stated): the bare (ungrouped) SIN form (FP-prone, like a bare SSN); the
  province-of-issue range on the first digit (a weak enrichment, not needed given the checksum);
  other national insurance numbers.
