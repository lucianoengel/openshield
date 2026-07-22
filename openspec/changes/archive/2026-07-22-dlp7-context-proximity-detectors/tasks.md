# Tasks

## 1. Proto
- [x] 1.1 Add `DETECTOR_TYPE_PASSPORT = 20` and `DETECTOR_TYPE_DRIVERS_LICENSE = 21` to
  `proto/openshield/v1/classification.proto`. `make proto`; commit generated `corev1`.

## 2. Context primitive + detectors
- [x] 2.1 `internal/classify/context.go`: `contextNear(valueRe, keywordRe *regexp.Regexp, window int,
  text []byte) int` — for each value match, count it (de-duplicated on the normalized value) only if the
  keyword regex matches within `window` bytes before or after the value's span.
- [x] 2.2 A `passport` detector (`DETECTOR_TYPE_PASSPORT`): value `\b[A-Z]?\d{8,9}\b`, keywords
  `passport`, window ~40, moderate confidence. A `driversLicense` detector (`DETECTOR_TYPE_DRIVERS_LICENSE`):
  value `\b[A-Z0-9]{5,20}\b`, keywords `driver'?s?\s+licen[sc]e|\bdl\s*(no|number|#)`, window ~40,
  moderate confidence.
- [x] 2.3 Add both to `New()`.

## 3. Tests
- [x] 3.1 A passport number NEAR "passport" → a `DETECTOR_TYPE_PASSPORT` hit; the SAME number with no
  keyword nearby → no hit; "passport" alone (no value) → no hit; two occurrences de-dup to a count that
  reflects distinct values.
- [x] 3.2 A driver's license NEAR "driver's license"/"DL #" → a `DETECTOR_TYPE_DRIVERS_LICENSE` hit; the
  same value with no keyword → no hit.
- [x] 3.3 Through the full classifier (`New().Classify`): a document with a passport near its keyword
  reports the passport type and does not report it when the keyword is absent.

## 4. Mutation guards
- [x] 4.1 Make `contextNear` ignore the keyword (count every value) → the value-without-keyword test
  (3.1) FAILs (a bare number fires). Revert.
- [x] 4.2 Make the window huge (whole document) → a value with its keyword at the far end of a long
  document fires when it should not (a targeted test with a value and a distant keyword). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D199) — DLP-7 context-proximity detection; weak-format IDs are
  context-REQUIRED; byte-window heuristic; passport + driver's license; more countries/IDs reuse the
  primitive; distinct detector types.
- [x] 5.2 `docs/architecture-roadmap.md`: note DLP-7 context/proximity + passport/DL shipped.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync the delta into
  `openspec/specs/classification-contract/spec.md`.
