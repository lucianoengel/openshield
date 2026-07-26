## Context

`PublishRisk(subject, score)` has exactly one caller: `observePeer`, the server-side peer-UEBA detector. The
gateway's `RiskStore` therefore holds a purely behavioral number, and a Zero-Trust access decision reading it
is blind to every other domain — even though D241 made every domain write `unified_alerts` and D203 gave
those alerts a shared entity.

## Goals / Non-Goals

**Goals:** entity-scoped, cross-domain risk; published to every alias; recency-weighted; never lowers an
existing signal.

**Non-Goals:** calibration, continuous decay, endpoint-side consumption, replacing peer-UEBA.

## Decisions

### D-1: Derive from severity buckets, not a new scale

Each alert contributes its bucket's floor (`critical` 0.90, `high` 0.75, `medium` 0.50, `low` 0.25 — the
`severityFloor` mapping ADR-10 already defines), scaled by recency. The entity's risk is the MAXIMUM
contribution, not a sum.

Max rather than sum, deliberately: summing makes risk a function of alert VOLUME, so a noisy-but-benign
asset outranks a quietly-compromised one, and it lets an attacker suppress attention by keeping counts low
elsewhere. Max asks "what is the worst thing we know about this asset", which is the question an access
decision is actually asking.

### D-2: Recency as a linear decay across the window

Weight = 1 − age/window, floored at zero. A critical alert an hour into a 24-hour window still dominates; a
critical from 23 hours ago barely registers. Linear rather than exponential because the shape is a
heuristic either way and linear is inspectable by an operator reading the number.

### D-3: Publish to every alias

A gateway request authorizes on a USER identity (ZT-3); an endpoint alert is keyed by a DEVICE pseudonym.
Publishing only the device alias would leave the access proxy — the actual consumer — never matching. So the
entity's aliases are enumerated and each is published, which is the device⋈user link doing real work rather
than only grouping incidents.

### D-4: Highest wins at the consumer

`RiskStore.Set` becomes "raise, never lower" for published risk. Turning cross-domain aggregation on must
not be able to make a subject look SAFER than the behavioral signal already says. The cost is that risk
decays only when the store is restarted or a future ticket adds explicit decay — stated rather than hidden.

## Risks / Trade-offs

- **It is a heuristic wearing a number.** Documented in the proposal; no downstream may treat it as evidence.
- **Raise-never-lower means risk is sticky** until process restart. A deliberate asymmetry (fail toward
  suspicion for an access decision), and the honest cost of not having decay yet.
- **Max hides breadth**: an entity with five distinct high alerts scores the same as one with a single high.
  Breadth is already XDR-4's job (domain_count on the incident), so duplicating it here would double-count.
- **Recomputation is stepwise**, on the SOAR-2 interval — risk is not live between ticks.

## Migration Plan

Additive: nothing publishes entity risk until the scheduled loop is running and alerts exist.
