## Context

The roadmap flagged D3 as "a distribution decision": admin-authorable rules raise the D14
tension (the server must not be able to push control). The T2 model resolves it — the
server distributes DATA the node verifies; it never commands.

## Goals / Non-Goals

**Goals:** operator-authored declarative detectors, distributed signed, loaded fail-closed;
no code-execution or ReDoS surface from a rule.

**Non-Goals:** per-rule policy routing; the wire delivery channel; policy (vs detector)
bundles; a UI.

## Decisions

**Sign the bundle; verify before interpreting it (T2/D14).** `SignedRuleBundle` carries the
marshaled `RuleBundle` and an Ed25519 signature over those exact bytes. `LoadSignedRules`
verifies against a TRUSTED OPERATOR key BEFORE unmarshaling the inner bundle — an unverified
bundle's contents never reach the regex compiler. A compromised control plane can
distribute a bundle but cannot forge the operator signature, so it cannot inject rules. This
is the same T2 shape as risk (D91) and posture (D92): the server provides data, the node
decides what to trust.

**Declarative rules, never code.** A rule is a regex pattern + a NAMED built-in validator
(NONE/LUHN), so authoring cannot introduce a code path. Go's `regexp` is RE2 — linear time,
no catastrophic backtracking — so a hostile pattern cannot ReDoS. Bundles are bounded (256
rules, 4 KB pattern) so a bundle is not itself an exhaustion vector.

**Custom hits report a generic type (no leak).** A per-rule NAME could itself leak what it
detects (a rule named for a customer), reintroducing the leak the closed enum prevents
(D10/D29). So every custom rule reports `DETECTOR_TYPE_CUSTOM`; the rule_id is for bundle
management, not surfaced to the pipeline. Per-rule policy routing (a rule id in the
contract) is a deliberate follow-up.

**All-or-nothing loading.** One bad rule fails the whole bundle — a partially-loaded bundle
is an ambiguous security state (which rules are active?). The node either runs the exact
approved set or none of it.

## Risks / Trade-offs

- **Custom rules aggregate under CUSTOM.** A policy cannot yet distinguish two custom rules;
  it acts on "a custom rule fired". Per-rule routing needs a contract field — deferred.
- **Key custody is the trust root** (like the ledger signer, D16). The operator signing key
  must be protected; a leaked key lets an attacker author rules. Out of scope here as
  everywhere: key management is a deployment concern.
