# T-004 — Peer-baseline UEBA on paper: does the pipeline hold?

**Date:** 2026-07-20 · **No code.** · **Verdict: the pipeline needs one addition. Found on
paper, in an afternoon, instead of in year three.**

## Why this exercise

The project's central claim is that a fixed pipeline absorbs a decade of capabilities by only
adding plugins:

```
Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
```

The CI fitness test (T-014) checks that adding a Connector produces zero diffs in core. Review
finding A1 pointed out that this proves very little: an S3 connector is *structurally isomorphic*
to a fanotify connector — another producer of resource-created events — so it passes whether or
not the abstraction is sound.

Peer-baseline UEBA is the opposite. It is stateful, aggregating, cross-entity and temporal. If
the pipeline stretches to cover it, the ten-year claim has real evidence. If it does not, better
to know now.

## What peer-baseline UEBA actually requires

Comparing a person against their peers, rather than against their own history, needs:

1. **Persisted per-entity baselines** — "typical" behaviour for a user and for their peer group,
   accumulated over weeks.
2. **Cross-entity aggregation** — a peer group is many subjects, so the computation spans data
   from many agents.
3. **Temporal windows** — rolling 30/90-day baselines, with decay.
4. **Continuous re-scoring** — a score changes as new events arrive, not only when an event is
   evaluated.
5. **The score influencing decisions** — otherwise it is a dashboard, not a security control.

Requirements 1-4 are unsurprising. **Requirement 5 is where the pipeline breaks.**

## The finding: a linear pipeline cannot feed Analytics back into Policy

Analytics sits at the *end* of the pipeline. Policy sits in the *middle*. A useful risk score is
consumed by Policy — "warn on upload if the subject's risk score is elevated" — which means the
output of the last stage must become an input to a middle stage.

That is a cycle, and the pipeline is a line.

The tempting workarounds are all worse than they look:

- **Make Analytics a stage before Policy.** Then Analytics cannot see the Decision, which is one
  of its most valuable inputs (a user accumulating blocked attempts is precisely the signal).
  It also puts a stateful cross-entity store inside the per-event hot path, which D24 exists to
  prevent — the fanotify permission window is 1-3µs typical, and a baseline lookup across a
  fleet is not.
- **Two-pass evaluation.** Run the pipeline, compute analytics, run it again. This doubles the
  work, and the second pass sees a different world than the first, so replay (a T-022
  requirement) no longer reproduces a Decision deterministically.
- **Let the Policy stage query the analytics store directly.** This is the one that looks
  harmless and is the most corrosive: Policy would import a store owned by another capability,
  which is precisely the stage-to-stage coupling the dispatcher was designed to make impossible.
  It would pass the CI fitness test — no core package diff — while destroying the property the
  test exists to protect. A concrete example of A1's warning that the test is Goodhart-able.

## What the pipeline actually needs

**An enrichment input to Policy that is fed asynchronously and read synchronously.**

Review finding **A6 already flagged this** as a missing abstraction — "local policy needs asset
tier, exception groups, org unit; where does that come from and how does it stay fresh?" — and
it was recorded as undesigned. T-004 confirms it is not optional, and that risk scores are the
same shape as those other inputs:

```
                    ┌──────────────────────────────────┐
                    │  Context (read-only, in-process) │
                    │  risk score · asset tier ·       │
                    │  exception groups · org unit     │
                    └────────────▲──────────┬──────────┘
   async, off the hot path       │          │  sync read, hot path
                                 │          ▼
Event → Classification → Policy(+Context) → Decision → Enforcement → Audit
                                                          │
                                                          ▼
                                              Analytics (stateful, server-side)
```

Properties this must have, all of which follow from constraints already established:

- **Reads are local and synchronous.** Policy evaluation happens on the endpoint (D1) and must
  not wait on the network — the same reasoning as D24.
- **Writes are asynchronous and off the hot path.** Analytics computes server-side and pushes
  updated context to agents; an agent that has not received an update uses the stale value and
  keeps working. Offline-capable is a stated principle.
- **Context is versioned, and the version is recorded in the Decision.** Otherwise replay is
  broken: re-running an Event against today's context would produce a different Decision than
  the one recorded, and T-022 requires replay to reproduce. **This is a change to the Decision
  contract** — it needs a `context_version` field.
- **Context is data, not code.** A closed, typed set of enrichment values. If it became an
  arbitrary key-value bag, it would be an open surface through which a compromised control plane
  could influence decisions — the same threat D14 closed for actions.

## Verdict

**Does peer-UEBA require core changes? Yes — one, and it is small:**

1. A `Context` type and a read-only accessor available to Policy (new, in `internal/core`).
2. A `context_version` field on `Decision` (a change to an existing contract).
3. An asynchronous context-update path on the transport (an addition, not a redesign).

**Does that falsify the ten-year claim? No — but it narrows it honestly.**

The claim "new capabilities never require core changes" is **false as stated**. The accurate
version is:

> New capabilities of the same *shape* as existing ones — event producers, classifiers,
> policies, enforcers — require no core changes. Capabilities that introduce a new *shape* of
> data flow require a core addition, and the pipeline's value is that such additions are rare,
> small, and identifiable in advance.

That is a weaker claim and a true one. It should replace the stronger claim in the README and
the brief, because the stronger version will be falsified in public the first time someone tries
to add exactly this capability.

## Consequences to act on

| # | Action | Where |
|---|---|---|
| 1 | Add `context_version` to `Decision` **now**, while there are no consumers. Retrofitting a field into a hash-chained audit ledger (T-009) is expensive. | New ticket, before T-009 |
| 2 | Design the `Context` abstraction (A6). Do not implement it in Phase 1 — no capability needs it yet — but let the Decision contract accommodate it. | New ticket, Phase 2 |
| 3 | Reword the zero-core-change claim in README and `docs/brief.md` to the accurate version above. | Doc change |
| 4 | Record that the CI fitness test is necessary but not sufficient, with this document as the worked example. | `docs/decisions.md` |

## What this exercise cost and returned

An afternoon of paper design, no code. It found a contract change that would otherwise have been
discovered after the audit ledger was built — at which point adding a field to a hash-chained
record means a migration and a break in the chain's continuity.

It also produced a concrete instance of the fitness test being gameable: the "let Policy query
the analytics store" workaround passes CI and destroys the architecture. That is worth more than
the design itself, because it shows the test cannot be trusted alone.
