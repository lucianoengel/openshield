# Tasks — DLP-7 phone detector (D130)

## 1. Detector

- [x] 1.1 internal/classify/phone.go: phone detector (E.164/parenthesised/separated formats + 7–15 digit count, low conf); registered in New().

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: real formatted numbers detected; bare runs / timestamps / too-few-digit / +format-with-few-digits read clean.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D130.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| digit-count validator disabled | a +formatted string with 2 digits then trips |
| regex accepts bare 10-digit runs | an order-id run then trips |
