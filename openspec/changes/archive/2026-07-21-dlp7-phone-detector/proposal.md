## Why

DLP-7 (P1, part — detection breadth). The `DETECTOR_TYPE_PHONE` enum has existed since the
schema but had NO detector — a claimed type with no implementation. This adds a phone-number
detector with the format+FP discipline the other validator-free detectors use.

## What Changes

- `internal/classify/phone.go`: a `phone` detector requiring DISTINCTIVE phone formatting
  (E.164 +country, parenthesised area code, or separated NXX-NXX-XXXX) and a plausible digit
  count (7–15), at low confidence — never a bare digit run. Registered in the default classifier.

## Capabilities

### Modified Capabilities
- `pattern-classifier`: adds a phone-number detector.

## Impact

- New `internal/classify/phone.go`; `docs/decisions.md` D130.
- Proven: real formatted numbers (US parenthesised/dashed/dotted, E.164 international, +1) are
  detected; a bare 10-digit run, a unix timestamp, too-few-digit shapes, and a +formatted
  string with too few DIGITS read CLEAN (the FP discipline — format + digit-count both required).
  Guards mutation-tested (digit-count-validator-disabled → a too-short +format trips; regex-
  accepts-bare-runs → an order id trips).
- NOT in scope (stated): country-specific national number plans / exact area-code validity
  (there is no checksum — like SSN, the confidence is capped low to reflect format-only
  evidence); vanity numbers (1-800-FLOWERS); phone numbers spelled with words.
