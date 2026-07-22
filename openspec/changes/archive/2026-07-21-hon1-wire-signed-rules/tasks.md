# Tasks — HON-1 wire signed rules into the worker (D118)

## 1. Wire

- [x] 1.1 cmd/openshield-worker loadClassifier: load OPENSHIELD_RULES_BUNDLE verified against OPENSHIELD_RULES_PUBKEY via WithRules; fail-closed on rules, built-ins preserved.

## 2. Proof (binary package; guard mutation-tested)

- [x] 2.1 **Test**: a signed bundle → custom rule fires + built-ins work; tampered + wrong-key → no custom rule, built-ins still classify.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D118.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| custom rules never applied (never wire) | the signed rule no longer fires |
| (ignore LoadSignedRules error) | SURVIVES — LoadSignedRules is itself fail-closed (D100), returns no rules on a bad bundle; honest defense in depth |
