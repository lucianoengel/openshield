## Context

`policy.Stage` holds one prepared Rego query and returns its Decision. `NewPack(name)` builds a Stage
from a single pack module; `NewDefault` from `default.rego`. The engine/gateway pick one via
`OPENSHIELD_POLICY_PACK`, so a pack **replaces** the default. Each module — `default.rego`,
`packs/pci.rego`, … — is a self-contained `package openshield` defining `decision` as a complete rule
(`decision := {…ALERT…} if hit`, `decision := {…ALLOW…} if not hit`). Two such modules cannot share a
package (two different `decision` values for one input is an OPA eval conflict), so composition cannot
be textual concatenation. ADR-5 is the governing decision.

## Goals / Non-Goals

**Goals:**
- Packs COMPOSE with the default; selecting a pack never removes a protection (behavioral alerting and
  strong-detector alerts survive every pack).
- Combine the modules' Decisions under a most-restrictive-wins lattice over the data-plane verbs.
- A compliance pack can never escalate to a process-control verb (`DENY_EXEC`/`KILL_PROCESS`).
- Stamp the composed bundle identity on the Decision; no proto/core change; determinism (D27) intact.

**Non-Goals:**
- Changing the pack Rego contents or adding new packs.
- A general policy-priority/override DSL — the lattice is fixed and total.
- Enforcement behavior — packs stay observe-only (ALERT); enforcement remains the operator's separate
  `OPENSHIELD_ENFORCE` opt-in.

## Decisions

### D-a · Combine Decisions in Go, one prepared query per module
Each module is prepared as its own `rego.PreparedEvalQuery` (unchanged `New` path, restricted
capabilities). `Stage` becomes a list of `{name, query}` members; `Run` builds the input once, evals
every member, extracts each candidate `(action, reason, confidence)` with the existing `decision()`
logic, and combines. A single-policy Stage is a 1-member composite whose combine returns that member
verbatim — so `New`/`NewDefault`/`NewPack` keep byte-identical behavior and every existing policy test
stays green.

*Alternative considered:* a Rego meta-module that imports each pack under a distinct package and takes
the max. **Rejected** — it needs the packs rewritten into sub-packages (they are flat `package
openshield`), pushes the lattice into Rego where it is harder to test and to keep the process-verb
guard, and complicates the restricted-capability compile. Combining in Go keeps the packs untouched
and the lattice unit-testable.

### D-b · The lattice ranks data-plane verbs; a higher rank wins
`ALLOW(0) < ALERT(1) < REDIRECT(2) < ENCRYPT_LOCAL(3) < QUARANTINE_LOCAL(4) < BLOCK(5)` (QUARANTINE
outranks ENCRYPT per ADR-5). The winner is the candidate with the highest rank; its `reason` and
`confidence` are carried onto the composed Decision. Ties (same action) keep the first member's
reason deterministically (member order is default-first, then packs in the given order, then custom).

### D-c · Process-control verbs are off-lattice, with a pack guard
`DENY_EXEC`/`KILL_PROCESS` are not ranked. If a **compliance pack** member yields one, `NewComposite`
(and the combine) returns a hard error — a pack can never silently escalate to killing a process
(ADR-5). The default and an operator custom module MAY yield a process verb; when one does (only on a
process event, where packs yield `ALLOW`), the process verb is the decision and is NOT down-ranked by
the data lattice — a genuine `KILL_PROCESS` on a process event is not overridden by a pack's `ALLOW`.
Because a data event never produces a process verb (the behavioral rule is undefined for it) and a
process event's packs only yield `ALLOW`, the two axes never actually conflict for one input — this
precedence rule is the formal statement of ADR-5's "process and data verbs never combine".

### D-d · Composed bundle identity, no proto change
The composed Stage stamps `PolicyId = "openshield.composite"` and
`PolicyVersion = "<member1>+<member2>+…"` in stable order (e.g. `default+pci+hipaa`), reusing the
existing Decision fields so the ledger records which bundle produced each Decision. A 1-member Stage
keeps its original id/version (no `composite` relabeling for the plain default/pack cases used by
existing callers that pass an explicit id).

### D-e · Wiring: default is always a member; packs add to it
`NewComposite(ctx, packNames []string, customModule string)` prepends the default, appends each named
pack (unknown name → error, as today), and appends the custom module if non-empty.
`OPENSHIELD_POLICY_PACK` (singular, back-compat) and `OPENSHIELD_POLICY_PACKS` (comma list) feed
`packNames`; `OPENSHIELD_POLICY_CUSTOM` is an optional Rego file path. With none set, the engine/gateway
still use `NewDefault` (a plain 1-member Stage), unchanged.

## Risks / Trade-offs

- **Behavioral change for existing `OPENSHIELD_POLICY_PACK` users** (now composes, was replace) → this
  is the fix; it only ever ADDS alerts (more restrictive), never removes them. Documented as a
  migration note; a test proves default protections survive.
- **N evals per event instead of 1** → packs are tiny and the engine is already off the hot path
  (observe-only, D34 note); N is the small operator-chosen pack count. Acceptable; no hot-path change.
- **A pack author could add a process verb later** → the composition guard rejects it at
  construction/first-eval, and a test asserts the rejection, so it fails loudly rather than silently
  escalating.
- **Determinism (D27)** → combining is a pure function of the per-module results; the restricted
  capabilities and input are unchanged, so identical input → identical composed Decision.

## Migration Plan

1. Ship `NewComposite` + the combine; `New`/`NewDefault`/`NewPack` become thin (1-member) wrappers,
   behavior-identical.
2. Rewire the two cmds; document that `OPENSHIELD_POLICY_PACK` now composes and `OPENSHIELD_POLICY_PACKS`
   / `OPENSHIELD_POLICY_CUSTOM` exist. Rollback is reverting the commit — packs return to replace
   (the prior, weaker behavior), never worse than today.

## Open Questions

None — ADR-5 fixes the lattice, the process-verb exclusion, and the compose-not-replace rule.
