# Tasks — HON-3 wire engine enforcement (D117)

## 1. Wire

- [x] 1.1 cmd/openshield-engine registerEnforcers: quarantine always under OPENSHIELD_ENFORCE, encrypt-local on a key/pubkey; observe-only default.

## 2. Proof (binary package; guards mutation-tested)

- [x] 2.1 **Test**: with OPENSHIELD_ENFORCE a CPF-flagged file is quarantined + "enforced" audited; without, no enforcer + file untouched.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D117.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| quarantine never registered (the HON-3 bug) | the file is not quarantined |
| register regardless of the flag | observe-only test finds an enforcer registered |
