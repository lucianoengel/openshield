# Design — wire peer-UEBA into the fleet telemetry stream

## The architectural point (D54)

peer-UEBA has TWO possible integration seams, and they are not the same:

1. **Endpoint policy Context** (proven in D53): `Analyzer.Resolver()` plugs into
   `Dispatcher.ResolveContext`, so a resolved risk flows into endpoint policy.
   This proved the ONE core seam a new-shape capability needs.
2. **Server-side fleet detection** (this change): the Analyzer consumes the
   control plane's verified telemetry stream and produces investigations.

Seam 2 is the one the running system uses, because the data peer-UEBA needs — the
whole fleet's activity — exists ONLY at the control plane. Seam 1 could only fire
if the server fed context back to agents, and D14 forbids that (the control plane
observes and coordinates; it does NOT control agents). So the honest wiring is:
**peer-UEBA runs server-side and emits alerts; it never steers an agent.** D54
records this.

## Where the analyzer lives

A `*peerueba.Analyzer` field on `Server`, nil by default. `controlplane` importing
`internal/analytics/peerueba` is allowed — the capability boundary bans only
`internal/core` from importing analytics, and the control plane is not core. The
check (`check-capability-boundary.sh`) still guards core; nothing new is exempted.

## The hook

In `handleSigned`, AFTER a message verifies and is persisted (an unverified
message is not evidence and must not move a baseline), if the analyzer is enabled
and the kind is `event`:

1. decode the event, read `subject.pseudonymous_id`;
2. `analyzer.Observe(subjectID)`;
3. `ctx := analyzer.ContextFor(subjectID)`; if `ctx.HasRiskScore &&
   ctx.RiskScore >= threshold`, record a peer alert — subject to the cooldown.

Order matters: Observe THEN evaluate, so the subject's own event is in the
baseline it is judged against (consistent with the endpoint resolver, which
resolves after the event exists).

## Rising-edge cooldown

Without dampening, an outlier scores high on EVERY subsequent event and emits an
alert each time. The cooldown records the last alert time per subject and
suppresses re-alerting within a window (configurable; a small default). It is a
rising-edge/rate limiter, NOT a risk change — the risk is still computed each
event; only the ALERT is throttled. A test asserts N events from one outlier
produce ONE alert, not N.

## The peer_alerts store (migration 009)

A dedicated table, not `fleet_telemetry` — a peer alert is a server-side
DERIVATION, not received telemetry, and conflating them would let a derivation
masquerade as an agent-attested row (the same category error D40/D41 guard). It
is NOT the evidentiary ledger either (D38): it is a fleet-aggregate detection.

```
peer_alerts(
  id BIGSERIAL PRIMARY KEY,
  subject_id TEXT NOT NULL,
  risk_score DOUBLE PRECISION NOT NULL,
  context_version TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
```

The alert names the pseudonymous SUBJECT (whose behaviour), not an agent —
peer-UEBA compares subjects across the fleet, and a subject may report via many
agents. Pseudonymous by default (D23); re-identification is a separate,
audited operator action, out of scope here.

## Threshold and enablement

Both come from explicit configuration on the Server (e.g. `EnablePeerUEBA bool`,
`PeerRiskThreshold float64`). Default disabled. Enabling it is the D23
consent/DPIA decision, made by the operator, not a code default that quietly
profiles a fleet.

## What this does NOT do

- No feedback to agents (D14).
- No re-identification of subjects (D23).
- The z-score risk model is unchanged — still a toy that proves the SHAPE, not a
  tuned detector. Detection quality is explicitly out of scope.
