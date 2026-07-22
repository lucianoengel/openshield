## Why

HON-1 (P1). `LoadSignedRules`/`WithRules` — the D100/D3 "admin-authorable signed custom
rules", committed as "Phase D complete" — were never called by any binary; the worker built a
bare `classify.New()` (built-ins only), so the feature was UNREACHABLE in production. This
wires it into the worker.

## What Changes

- `cmd/openshield-worker`: `loadClassifier` merges operator-authored SIGNED custom rules from
  `OPENSHIELD_RULES_BUNDLE`, verified against `OPENSHIELD_RULES_PUBKEY`, via `WithRules`.
  Fail-closed on the rules — a missing key or an unverified/unreadable bundle loads NO custom
  rules and the worker runs with the built-ins (availability preserved), never trusting
  unverified rules.

## Capabilities

### Modified Capabilities
- `pattern-classifier`: the worker loads signed custom rules when configured.

## Impact

- `cmd/openshield-worker/main.go`; `docs/decisions.md` D118.
- Proven (binary package, real signed bundle on disk): a signed bundle causes a custom
  detector to fire through the worker classifier, alongside the built-ins; a TAMPERED bundle
  and a WRONG-KEY bundle load NOTHING (no custom rule fires) while the built-ins still
  classify (the worker does not refuse to run). Guard mutation-tested: **never-wire (custom
  rules not applied) fails the test**. (The verify itself is LoadSignedRules' fail-closed,
  proven in D100.)
- NOT in scope (stated): an operator rule-authoring/signing TOOL (a provision subcommand to
  emit a signed bundle — a small follow-up; today an operator signs with the SignRuleBundle
  API); hot-reload of the bundle (SIGHUP, like the CA rotation D79); per-rule policy routing
  (D100 follow-up). Preserves the no-leak (DETECTOR_TYPE_CUSTOM) and path-vs-content
  guarantees of D100.
