## Context

`Dispatcher.Dispatch` builds `st := &State{Event: e}` — Context always nil, no injection. The policy
`buildInput` hardcodes `"context": nil`. `core.Context{Version, ComputedAt, RiskScore, HasRiskScore,
AssetTier, OrgUnit, ExceptionGroups}` exists (D28), as does `Decision.context_version` (D27). Nothing
computes or resolves a Context. Peer-UEBA is the new-shape capability D26 names as the real test.

## Goals / Non-Goals

**Goals:**
- The ONE small core change peer-UEBA needs: a Context resolver hook on the Dispatcher.
- A stateful cross-entity peer-UEBA analyzer producing a Context, entirely outside core.
- The policy reading the risk score; a rule escalating on high peer risk; end to end.
- The fitness verdict recorded.

**Non-Goals:**
- A production risk model; running in the permission window; enforcement (Phase 2); anything beyond
  the one identified core change.

## Decisions

### Core change: Dispatcher.ResolveContext
`Dispatcher.ResolveContext func(*corev1.Event) *Context`. In Dispatch, after building the State:
`if d.ResolveContext != nil { st.Context = d.ResolveContext(e) }`. Nil default → nil Context →
today's behaviour. This is the whole core change — one field and one guarded call. It is named in
the proposal and here as the D26 "small identifiable addition".

### peerueba.Analyzer (capability, outside core)
`internal/analytics/peerueba`. `Observe(subjectID string)` increments a per-subject activity count;
the analyzer holds the population (all subjects). `ContextFor(subjectID) *core.Context` computes the
peer-RELATIVE risk: the subject's count as a z-score against the population mean/stddev, mapped to
[0,1]; `HasRiskScore=true`, `Version` a monotonic snapshot id (D27). This is stateful (accumulates)
and cross-entity (peer-relative) — the new shape. It is thread-safe (a mutex) since Observe (stream)
and ContextFor (resolve) race.

A resolver adapter: `analyzer.Resolver()` returns `func(*Event) *Context` reading the event's
pseudonymous subject — plugged into `Dispatcher.ResolveContext`. The analyzer imports core (for
Context); core does NOT import the analyzer (capability boundary check).

### Policy reads the risk score
`buildInput` sets `"context"` to `{ "risk_score": ..., "has_risk_score": ... }` when `State.Context`
is present (a policy-package change). A policy rule escalates to ALERT when `has_risk_score` and
`risk_score >= threshold`, even with no PII hit — the peer signal alone. A test policy exercises it;
the shipped default stays PII-driven and observe-only.

### The verdict
Recorded in docs and a test: peer-UEBA needed exactly ONE core change (ResolveContext). A test
asserts the resolver flows a Context to the policy, and the capability-boundary check still passes
(analyzer is not imported by core). The zero-core-change claim is thus shown false, the small-change
claim true.

## Risks / Trade-offs

- **A core change to a frozen-ish contract.** It is one field, guarded, nil-default — the minimum,
  and exactly what D26 anticipated. Admitted, not hidden; the alternative (pretending none was
  needed) is the overclaim the fitness test exposes.
- **Toy risk model.** z-score over an activity count proves the shape, not detection quality. Stated.
- **Statefulness + concurrency.** The analyzer is mutex-guarded; Observe and ContextFor are safe to
  call concurrently.
- **Off by default.** Nil resolver = no Context = Phase-1 observe-only unchanged (D1/D23). Enabling
  peer-UEBA is opt-in with a consent/DPIA gate (D23), out of this change's scope to enforce.
