# Tasks — signed admin-authorable custom rules (D100)

## 1. Bundle + sign/verify/load

- [x] 1.1 Proto: DetectorRule/RuleBundle/SignedRuleBundle + RuleValidator + DETECTOR_TYPE_CUSTOM; regenerate.
- [x] 1.2 `internal/classify/rules.go`: SignRuleBundle (operator); LoadSignedRules (verify-before-parse, compile rules, fail-closed, all-or-nothing, bounded); customDetector (generic CUSTOM type); Classifier.WithRules.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: sign→verify→load→a custom rule fires (as CUSTOM) with built-ins intact; LUHN validator applied (invalid number doesn't fire); wrong-key/tampered/unsigned/garbage bundle loads NOTHING + errors; a bad rule fails the whole bundle.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D100.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| signature verification skipped | wrong-key/tampered bundle then loads (must fail closed) |
| bad rule skipped instead of failing the bundle | a bad-rule bundle then loads partially |
| LUHN validator replaced with always-true | a Luhn-INVALID number then fires the custom rule |
| (empty-signature guard removed) | NOT independently observable — ed25519.Verify returns false on an empty sig, so unsigned is still rejected; kept as a clearer error |
