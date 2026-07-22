## Why

The landed detectors are strong where the identifier has a checksum (CPF, card, IBAN, SIN, NPI, NHS) or a
distinctive structure (EIN, private keys, cloud keys). But many sensitive identifiers have **weak,
variable formats and no checksum** — a passport number, a driver's license — so a format-only rule either
misses them or floods on any 9-digit run. The DLP way to detect these without drowning in false positives
is **context proximity**: fire only when the value pattern appears *near a context keyword* ("passport",
"driver's license"). This is the DLP-7 primitive, and it unlocks a class of detectors format-alone can't
do safely.

## What Changes

- A `contextNear` detection primitive: count distinct values matching a pattern that have a context
  keyword within a proximity window (before or after), de-duplicated — content-free, like the other
  detectors.
- Two context-gated detectors built on it: **US passport** (a 9-digit or letter+8-digit number near
  "passport") and **US driver's license** (a state-variable alphanumeric near "driver's license"/"DL").
  Both require the keyword, so a bare number does not fire.
- Distinct `DETECTOR_TYPE_PASSPORT` and `DETECTOR_TYPE_DRIVERS_LICENSE`, added to the default classifier.

## Capabilities

### New Capabilities
<!-- none — extends the pattern classifier -->

### Modified Capabilities
- `classification-contract`: adds keyword-proximity (context) detection and two context-gated identity
  detectors (passport, driver's license) — the low-false-positive way to detect weak-format identifiers.

## Impact

- **Code:** `DETECTOR_TYPE_PASSPORT`/`DETECTOR_TYPE_DRIVERS_LICENSE` (proto); a `contextNear` helper and
  two detectors in `internal/classify`, added to `New()`. Proven: a passport/DL number NEAR its keyword
  is detected; the SAME number with NO nearby keyword is NOT (the context precision); the keyword alone
  (no value) is not; matches de-dup. No content leaves the host — only type + confidence + count (D10).
- **Scope note (honest):** context proximity is a **byte-window** over the extracted text (a keyword
  within N bytes of the value), not linguistic parsing — a deliberately simple, low-FP heuristic; richer
  context (sentence structure, labels) is a refinement. The value patterns are US-oriented (passport
  9-digit, DL alphanumeric); **more countries / more weak-format IDs** are follow-ons that reuse this
  same primitive — and operators can already author their own context rules via the signed custom-rule
  surface. Driver's-license formats vary by state, so the detector is deliberately context-REQUIRED (the
  format alone is too generic to fire on its own).
