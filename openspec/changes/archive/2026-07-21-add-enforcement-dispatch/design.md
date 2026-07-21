## Context

`core.Enforcer{ Capabilities() []Action; Enforce(ctx, *Decision) error }` and `core.CanEnforce`
exist; the USB enforcer (T-020) implements them. The engine (Direction 2) processes an event to a
Decision and records it via the audit sink. Nothing invokes an enforcer. Inline blocking is
infeasible (T-002 budget), so enforcement is post-decision.

## Goals / Non-Goals

**Goals:**
- The engine dispatches a produced Decision to a matching registered enforcer, AFTER recording it.
- Enforcement failure is audited high-severity (D14).
- Observe-only default (no enforcers); a real quarantine-local file enforcer.

**Non-Goals:**
- Inline fanotify blocking (deferred, budget); new actions; preventing the triggering access.

## Decisions

### The engine gains an enforcer registry, invoked after Dispatch
`Engine.Enforcers []core.Enforcer`. `Process` runs the pipeline to a Decision (recorded by the audit
sink as today), then, if the Decision has an enforceable action and an enforcer advertises it, calls
`Enforce`. Order: record THEN enforce, so the audit shows the decision even if enforce fails or the
process dies. With no enforcers, Process is unchanged — observe-only (D1).

### Enforcement outcome is audited
On `Enforce` error, the engine appends a high-severity audit entry (outcome kind
"enforcement-failed", the action and stage) — a failed enforcement is auditable, not silent (D14).
A successful enforcement optionally records an "enforced" entry so the trail shows the action was
carried out. Both go through the same ledger the decision did.

### A concrete quarantine-local file enforcer
`internal/enforcers/quarantine`: `Enforcer{ mover Mover; dir string }`, Capabilities =
{QUARANTINE_LOCAL}. `Enforce` moves the flagged file to `dir` (0700, owner-only). The file path
comes from the Decision — BUT the Decision carries no target (the D39 gap). So the enforcer is
constructed per-event with the path, OR the engine passes the event's path to the enforcer through a
typed enforcement context. To avoid widening the Decision contract here, the engine builds a
per-event enforcer binding (the path it just classified) — the enforcement TARGET is the event the
engine holds, not something smuggled into the Decision. This keeps D14 (enforcer sees only the
Decision for the VERDICT) while giving enforcement the target from the pipeline State, not the wire.

`Mover` is an interface (rename/copy+remove); a fake records moves for the dispatch test, a real one
moves files for the filesystem test.

### Observe-only preserved and asserted
A test with no enforcers asserts the engine decides+records and enforces NOTHING. A test with the
quarantine enforcer and a QUARANTINE_LOCAL policy asserts the file is moved AND both the decision and
an enforcement outcome are recorded.

## Risks / Trade-offs

- **Post-decision, not prevention.** The file was already read; quarantine contains after the fact.
  Stated on every surface so "enforcement" is not read as "prevention" (D16). Inline blocking is the
  deferred hard piece.
- **The enforcement target is the engine's event, not the Decision.** Deliberate — avoids widening
  the hash-chained Decision contract (D39's deferred core addition) while enforcement genuinely needs
  a target. The enforcer still receives only the Decision for the verdict; the engine supplies the
  target from the State it already holds.
- **Quarantine defeatable by root** (D16). Contains a careless insider; audited. Honest bound.
- **Record-then-enforce leaves a window** where a decision is recorded but enforcement did not run
  (crash between). The audit shows the decision; on restart the un-enforced decision is visible.
  Acceptable — the trail is truthful about what happened. Noted.
