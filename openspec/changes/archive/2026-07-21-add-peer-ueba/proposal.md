# Add peer-baseline UEBA — the real architecture test (Direction 3)

## Why

D26 narrowed the zero-core-change claim and named its real test: a capability of a genuinely NEW
SHAPE, not a second connector isomorphic to what exists. The fitness test (T-014) is gameable and
proves little on its own; the honest test is building peer-baseline UEBA — stateful, cross-entity,
Analytics-shaped — and seeing whether the architecture absorbs it as a plugin or forces a core
change. T-004 designed it on paper and predicted it needs a small, identifiable core addition (the
`Context` seam), which was then added preemptively. This BUILDS it, and reports the verdict from
code, not paper.

**The verdict, found before writing the capability:** it DOES need one small core change, and it is
exactly identifiable. The `Dispatcher` builds `State{Event: e}` with `Context` always nil and no way
to inject a resolved one, and the policy hardcodes `context: nil`. So a capability that produces a
Context (a peer risk score Policy consults) cannot reach the pipeline without a hook. That is the
"small, identifiable core addition" D26 predicted a new-shape capability would need — the
architecture absorbs it, and the change is small and named, not sprawling.

## What changes

**One small core addition: a Context resolver on the Dispatcher.** `Dispatcher.ResolveContext
func(*Event) *Context`, called before the stages run, so a resolved Context reaches `State.Context`.
This is THE core change peer-UEBA requires — a single hook, not a redesign. With it nil (the default),
behaviour is exactly as today (Context stays nil, observe-only Phase 1).

**The peer-UEBA capability, entirely outside core.** `internal/analytics/peerueba`: a stateful,
cross-entity analyzer that observes events across subjects, maintains per-subject and peer-group
behavioural stats, and computes a peer-RELATIVE risk score (how anomalous a subject is vs its
peers). It produces a `core.Context{RiskScore, HasRiskScore, Version}`. It is an Analytics module,
not a per-event Stage — it aggregates the stream, which is precisely the new shape.

**The policy reads the risk score.** The policy input gains the Context's risk score (a
policy-package change, not core), and a policy rule escalates when peer risk is high — so the
capability actually influences a Decision, end to end.

**The fitness verdict, recorded.** This change documents that peer-UEBA needed exactly ONE small core
change (the resolver hook), naming it — validating D26's claim that a new-shape capability needs a
small, identifiable core addition, and disproving the stronger "zero core change" version the brief
implied.

## What this does NOT claim or cover

- **It is not a production UEBA.** The risk model is a simple peer z-score over an activity count —
  enough to prove the SHAPE (stateful, cross-entity, feeding a Context), not a tuned detector. Real
  behavioural features, decay, and false-positive control are later.
- **It is off by default.** `ResolveContext` nil = Context nil = observe-only Phase 1 unchanged (D1).
  Peer-UEBA is opt-in, and server-side/off-by-default with its own consent/DPIA gate (D23).
- **It does not run in the endpoint permission window.** The Context is RESOLVED before dispatch
  (D28), out of band from the analytics state; the resolver is a value lookup, not an in-window
  computation. The analyzer aggregates asynchronously.
- **The core change is real and admitted.** The zero-core-change claim is FALSE for a new-shape
  capability; this makes exactly one small change and says so. Pretending it needed none would be
  the overclaim the fitness test exists to expose.

## Decisions

Depends on **D26** (the claim under test; new shape needs a small core change), **D28** (the Context
seam — resolved value, closed typed set), **D23** (peer UEBA is server-side, gated, off by default),
**D27** (context_version, already on Decision), and **T-004** (the paper design this realises).

Establishes a new decision: **peer-UEBA is built and confirms D26 in code — it needed exactly ONE
small, identifiable core change (a `Dispatcher.ResolveContext` hook), no more; the architecture
absorbs a new-shape capability with a small named addition, and the stronger zero-core-change claim
is false.**
