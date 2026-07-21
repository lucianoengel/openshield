# Tasks — international financial + health PII (D98)

## 1. Detectors

- [x] 1.1 Proto: DETECTOR_TYPE_IBAN/HEALTH_DATA; regenerate.
- [x] 1.2 `internal/classify/international.go`: iban (mod-97 + per-country length, space-form normalized) + healthData (≥3 distinct terms, low conf); registered in New().

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: real IBANs (DE/GB/FR + spaced + letter BBAN) detected; wrong-check-digit, wrong-length (incl. a mod-97-valid wrong-length string), unknown-country rejected; multi-term health fires low-conf, single term does not.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D98.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| IBAN mod-97 check bypassed | a wrong-check-digit IBAN is then accepted |
| IBAN country/length guard dropped | a mod-97-valid but wrong-length GB string is then accepted |
| health multi-term threshold weakened to 1 | a single common health word then fires the detector |
