## Why

DLP-7 (D199) added the `contextNear` keyword-proximity primitive and passport/driver's-license
detectors, and the roadmap's DLP-7 remainder is "more countries/national-IDs (reuse the primitive)".
OpenShield already detects US/Canada/UK national IDs (SSN, CA-SIN, UK-NHS, NPI, EIN), but two of the
world's largest identity systems are blind spots: **India's Aadhaar** (1.3B holders) and the **UK
National Insurance Number (NINO)**. A DLP that cannot spot an Aadhaar or a NINO in exfiltrated content
misses a huge class of regulated PII.

## What Changes

- **India Aadhaar detector**: a 12-digit id validated by the **Verhoeff checksum** (the published
  Aadhaar validation) plus the first-digit constraint (2–9) — a real check-digit scheme, so a hit is
  strong, low-FP evidence and needs no context keyword.
- **UK NINO detector**: the `[prefix][6 digits][suffix]` format with the official prefix-letter
  exclusions, detected via the existing `contextNear` primitive (near a "national insurance"/"NINO"
  keyword) — reusing the DLP-7 mechanism exactly as the roadmap intends, since NINO has no checksum.
- Two new closed `DetectorType` enum values; both detectors registered in the built-in set.

No new detection MECHANISM — Aadhaar reuses the checksum-detector shape (like CA-SIN/NPI), NINO reuses
`contextNear` (like passport/DL).

## Capabilities

### New Capabilities
<!-- none: extends the existing pattern-classifier with two more national-ID detectors. -->

### Modified Capabilities
- `pattern-classifier`: adds India Aadhaar (Verhoeff-checksummed) and UK NINO (context-gated) detection.

## Impact

- `proto/openshield/v1/classification.proto`: `DETECTOR_TYPE_AADHAAR = 22`, `DETECTOR_TYPE_UK_NINO = 23`
  (+ `make proto`).
- `internal/classify`: an `aadhaar` detector + a `verhoeffValid` checksum; a `ukNINO` detector reusing
  `contextNear`; both registered in `New()`.
- `internal/store/postgres/postgres_test.go`: unaffected (no migration).
- No core change, no new dependency.
