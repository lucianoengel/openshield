## Why

Detection rules were code-only — an operator could not add a custom detector (an internal
project code, a customer-ID format) without a release. Phase D3 adds admin-authorable
detectors, distributed SIGNED. The hard part is the D14/T2 tension: rules must reach the
node WITHOUT giving a compromised control plane the power to inject them. The answer:
operator-authored, operator-SIGNED declarative rules that the node loads only after
verifying the signature — the server may distribute a bundle but cannot forge it.

## What Changes

- Proto: `DetectorRule` (rule_id, pattern, confidence, validator), `RuleBundle`,
  `SignedRuleBundle` (marshaled bundle + Ed25519 signature); `RuleValidator` enum
  (NONE/LUHN); `DETECTOR_TYPE_CUSTOM`.
- `internal/classify/rules.go`: `SignRuleBundle` (operator side) and `LoadSignedRules`
  (node side — verify signature against a trusted operator key, compile each rule to a
  runtime detector, fail-closed); `customDetector` (reports the generic CUSTOM type);
  `Classifier.WithRules` (built-ins + custom).

## Capabilities

### Modified Capabilities
- `pattern-classifier`: operator-authored, signed custom detector rules loaded fail-closed.

## Impact

- New `proto/…/rules.proto` (regenerated), `internal/classify/rules.go`; `docs/decisions.md`
  D100.
- Proven: an operator signs a bundle, the node verifies + loads it, and a custom rule fires
  (reported as CUSTOM — no per-rule name leaks) alongside the still-working built-ins; a
  LUHN-validated rule uses the built-in validator (a Luhn-invalid number does NOT fire); a
  wrong-key, tampered, unsigned, or garbage bundle loads NOTHING and errors (fail-closed —
  the T2/D14 security core); a bad rule (uncompilable regex, out-of-range confidence,
  unknown validator, over-long pattern) fails the WHOLE bundle (no partial load). Guards
  mutation-tested (signature-verify-skipped; bad-rule-skipped-not-failed; validator-not-applied).
- NOT in scope (stated): per-rule policy routing (a rule id in the classification contract —
  custom hits currently aggregate under CUSTOM; a contract change is a follow-up); the
  network distribution channel (reuse the signed fleet transport, like risk/posture — this
  ships the sign/verify/load core; the wire delivery is a follow-up); authorable POLICY
  bundles (this is detectors; policy signing is the analogous next piece); a rule-authoring
  UI. Rules are DECLARATIVE (pattern + named validator, never code), and Go's RE2 engine is
  linear-time (no ReDoS); bundles are bounded (rule count, pattern length).
