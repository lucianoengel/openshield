# T-030 — The enrichment Context: designing the seam, not the subsystem

**Date:** 2026-07-20 · **No code.** · Follows [T-004](design-t004-peer-ueba.md), which showed
this abstraction is required rather than optional.

## Scope, deliberately narrow

Review finding A6 flagged an undesigned abstraction: policy evaluation needs more than an Event
and a Classification. It needs asset tier, exception groups, org unit — and, per T-004, a risk
score. All are the same shape: **facts about the world that Policy consults but does not
compute.**

This design answers exactly one question:

> What does the Policy stage receive, and what are the rules governing it?

It deliberately does **not** design the enrichment subsystem — how contexts are computed,
distributed, cached, invalidated or reconciled. **Nothing in Phase 1 needs a Context**, and
designing a distribution system for zero consumers is the speculative generality that D7 warns
about. The cost of getting the *seam* wrong is a retrofit into the policy stage; the cost of
getting the *subsystem* wrong is months. So: seam now, subsystem when something needs it.

## Design

### Policy receives a Context value, not an accessor

```
Stage.Run(ctx, *State)     // State gains: Context *Context
```

**Chosen:** Context is a plain value carried on the pipeline `State`, populated before dispatch.

**Rejected: an accessor interface** (`ContextProvider.Get(subject)`). An accessor lets Policy
perform an unbounded lookup during evaluation, which puts a potential network call, cache miss
or lock inside the fanotify permission window that D24 exists to protect. A value that is
already resolved cannot do that.

The consequence is that whoever builds the `State` resolves the Context first, at a moment where
blocking is acceptable. That is the correct place for the cost to land.

### The Context is a closed, typed set

```
Context {
  version         string          // opaque; identifies the snapshot
  risk_score      float           // [0,1], absent = unknown, NOT 0
  asset_tier      enum            // UNSPECIFIED | STANDARD | SENSITIVE | CROWN_JEWEL
  org_unit        string          // pseudonymous identifier
  exception_groups []enum         // closed set of exemption reasons
}
```

**Not a `map[string]string`.** An open bag would be a surface through which a compromised control
plane could influence decisions by inventing keys a policy happens to read — the same threat D14
closed for the action set, arriving through a different door. Adding a context field should
require a schema change and a deliberate review, exactly as adding an action does.

**`risk_score` absent must not read as 0.** Absent means "not computed"; zero means "computed,
and this subject looks fine". Conflating them makes every subject look safe when the analytics
pipeline is down — a fail-open with no signal. Absence is represented explicitly and a policy
that reads it must handle the unknown case.

### Staleness is normal and must be visible

Context is written **asynchronously, off the hot path**, by the control plane. It is read
**synchronously** during evaluation. An agent that has not received an update uses what it has.

This follows from constraints already established: local-first evaluation (D1) means an agent
must decide without the network; offline-capable means it must keep working when the control
plane is gone.

The rule that makes this safe rather than merely convenient:

> A Context carries the time it was computed. A policy MAY condition on staleness. A Decision
> made against a stale Context is still valid and still recorded — but the staleness is
> observable, not hidden.

The alternative — refusing to decide without fresh context — converts a control-plane outage
into an endpoint failure, which is precisely the coupling this architecture avoids.

### Versioning is what keeps replay honest

`Decision.context_version` already exists (D27). The rule:

> Replay of a Decision MUST evaluate against the Context version recorded on it. Replaying
> against the current Context is a **different operation** — useful ("what would we decide
> today?"), but it is not replay and must not be presented as reproducing the original.

Without this, a risk score that drifts overnight would make yesterday's decisions
irreproducible, and the audit trail would stop being evidentiary.

**Consequence:** historical Contexts must be retrievable by version for as long as decisions
referencing them are retained. That is a retention obligation on the enrichment store, and it
interacts with the D20 purge requirements — a Context cannot be purged while a retained Decision
still points at it. Flagged here; owned by whoever builds the subsystem.

### Phase 1 behaviour

Context is **absent**. `State.Context` is nil, `Decision.context_version` is empty, and policies
consult nothing. The seam exists so that T-008's policy stage takes the right shape; the
subsystem is not built.

A policy that requires a Context field it does not have MUST fail explicitly rather than
substituting a default — the same reasoning as `risk_score` absence.

## What this does NOT decide

- How risk scores are computed (peer-baseline UEBA, its own capability).
- How Contexts reach agents — push, pull, piggyback on an existing channel. Needs the transport
  and control plane to exist first (T-023).
- Cache eviction, invalidation and reconciliation across a fleet.
- Whether asset tier comes from a CMDB, a policy file, or an inventory connector.
- Retention interaction with D20 purge, beyond flagging that it exists.

Each is real work and none of it belongs in Phase 1.

## Consequences for T-008

The policy stage should be written so that:

1. `State` has a `Context` field, nil in Phase 1.
2. Policy evaluation takes Context as an input rather than reaching for it.
3. A policy referencing an absent Context field fails explicitly, and the failure is auditable.
4. `Decision.context_version` is populated from the Context when present, empty otherwise.

That is roughly an hour of extra care in T-008, versus a retrofit through the policy stage, its
tests and any recorded decisions once policies exist.

## Honest assessment

This design is **worth doing now and would not have been worth doing a week ago.** T-004 turned
"we might need enrichment someday" into "peer-UEBA cannot work without it", which is what makes
the seam a known requirement rather than a guess.

The risk remains that the subsystem, when built, wants a shape this seam does not fit — for
instance if contexts turn out to need per-policy scoping rather than per-subject. The mitigation
is that the seam is small: a nil-able field on `State` and a populated string on `Decision`.
If it is wrong, the cost is proportional to its size.
