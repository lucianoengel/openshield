## Context

`core.Stage` is `{ Name() string; Run(ctx, *State) (Outcome, error) }`. A stage sees the pipeline
`State` (Event, Classification, Context) and returns an `Outcome`; `core.Decided(d)` terminates
with a Decision. The Decision type, the closed `Action` enum, `context_version`, and
`core.Replay`/`DecisionsEquivalent` already exist. This change adds the stage that produces the
Decision, outside core (core must not grow a policy-engine dependency — same boundary as the
ledger and transport).

OPA exposes capability restriction via `ast.Capabilities`: an engine can be prepared with a
builtin allowlist, and a policy referencing an absent builtin fails at `rego.PrepareForEval`.
That is the mechanism this design leans on.

## Goals / Non-Goals

**Goals:**
- Evaluate a local Rego policy over classification output and emit a well-formed Decision.
- Guarantee determinism and the absence of side effects by CONSTRUCTION (capability set), not by
  reviewing policy text.
- Enforce the closed action set: an action the enum does not define cannot become a Decision.
- Identical input → identical Decision, verified against `DecisionsEquivalent`.

**Non-Goals:**
- Policy distribution, versioning, hot reload (Phase 2 / T-023).
- Bounding policy CPU. The capability set removes side effects, not compute.
- Rich policy authoring. One file, prepared once.

## Decisions

### The capability set is an allowlist, and it is tested by trying to escape it
Build `ast.CapabilitiesForThisVersion()` then filter its `Builtins` to a small allowlist of pure
operators (comparison, arithmetic, membership, string ops, object/array manipulation). Everything
else — `http.send`, `net.lookup_ip_addr`, `time.*`, `rand.*`, `opa.runtime`, `io.jwt.*`,
`crypto.*` with entropy — is excluded. A policy that calls one fails to prepare.

The test does not assert the allowlist's contents (that rots as OPA adds builtins); it asserts the
BEHAVIOUR: a policy calling `http.send` fails to load, and a policy calling `time.now_ns` fails to
load. If a future OPA upgrade reintroduced a dangerous builtin into the default set, these tests
would still pass only if our filter kept excluding it.

### The policy contract: input shape and result shape
Input document handed to Rego:
```
{
  "purpose": "PURPOSE_DLP",
  "event": { "kind": "...", "subject_id": "..." },
  "classification": [ { "type": "DETECTOR_TYPE_CPF", "confidence": 0.95, "count": 2 }, ... ],
  "context": null            // Phase 1: always null (D28 seam)
}
```
Result the policy must produce at a fixed rule path (`data.openshield.decision`):
```
{ "action": "ALERT", "confidence": 0.95, "reason": "cpf detected above threshold" }
```
`action` is a bare enum name. The Go layer maps `"ALERT"` → `corev1.Action_ACTION_ALERT` through
an explicit table; an unknown or missing action is a stage error (a failed Outcome), never a
silent ALLOW — "the policy didn't say" and "the policy said allow" are different, and conflating
them would fail open.

### A missing decision is a decision to do nothing, recorded as such
If the policy yields no `decision` (no rule matched), the stage returns `ALLOW` with a reason of
"no policy rule matched" and the classification's max confidence. Observe-only means the honest
default is allow — but it is an EXPLICIT allow with a reason, distinguishable in the ledger from a
policy that affirmatively allowed. (It is NOT a pipeline failure: falling through a policy is
normal.)

### Determinism is enforced, then verified
The capability set removes the clock and randomness, so evaluation is a pure function of input.
The Decision's non-deterministic fields (`decision_id`, `decided_at`) are set by the Go layer, not
the policy, and are excluded from `DecisionsEquivalent`. A test dispatches the same Event twice
and asserts `DecisionsEquivalent`.

### policy_id / policy_version come from the loaded policy
The stage is constructed with an id and version (from the file/config), stamped onto every
Decision, so the ledger records which policy produced each — the precondition for replay against
the right policy.

## Risks / Trade-offs

- **OPA is a heavy dependency.** Justified by D6 (no custom IR) and amortised across Phase 2's
  real policy needs; kept entirely out of core, so `internal/core` stays clean (verified by
  `check-core-deps.sh`). Writing our own evaluator to save the dependency is the exact
  build-it-ourselves trap D7 warns killed prior projects.
- **Capability restriction could over-restrict a legitimate future policy.** Adding a pure builtin
  to the allowlist is a one-line, reviewable change with a clear security meaning. The default
  errs tight: a builtin is absent until someone argues it in.
- **Rego eval latency is low-ms, not µs.** Fine: policy is off the permission-response path in
  observe-only Phase 1. If Phase 2 enforcement needs a verdict inside the window, that is a
  known, separate problem (pre-evaluation / caching), flagged not solved here.
- **The bare-enum-name contract is stringly-typed at the Rego boundary.** Mitigated by the closed
  mapping table and a test that every enum value round-trips and that an unknown name errors.
