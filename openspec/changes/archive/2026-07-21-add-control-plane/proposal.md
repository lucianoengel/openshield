# Add the control plane service (T-023)

## Why

The server side is referenced everywhere and built nowhere: T-017 (mTLS enrollment), T-018
(heartbeat), the end-to-end verification steps, and the CLI's eventual fleet view all assume a
control plane exists. Today the agent transport can `Publish*` telemetry to NATS subjects and
nothing consumes them. This builds the consumer: a service that receives agent telemetry and
persists it, so "the server coordinates" has something coordinating.

## What changes

**A control-plane service (`internal/controlplane`) that subscribes to the agent telemetry
subjects and persists what it receives.** It subscribes to `openshield.v1.events`,
`.classifications`, `.decisions` — the exact subjects the transport publishes — decodes each
message, and writes it to a `fleet_telemetry` table keyed by agent, kind and event.

**It stores only boundary-safe telemetry, by construction.** The transport has no method for
`LocalClassification` (D10) — only the `ClassificationSummary` crosses the boundary — so the
control plane can only ever receive type+confidence+count, never content. The store inherits that
guarantee for free: there is no code path by which content could arrive.

**It is the fleet aggregator, NOT the per-agent forward-secure ledger.** The audit ledger (D12/
D30) is the agent's local, hash-chained, forward-secure system of record. The control-plane store
is the aggregate view across agents, for querying "what did the fleet see". Keeping them distinct
is deliberate: the evidentiary integrity guarantees live at the agent, and the aggregate is a
convenience view that does not, and must not claim to, carry them.

**It does NOT distribute policy.** Phase 1 policy is a local file (D1); the control plane
coordinates and observes, it does not push policy or actions (D14 — "the server coordinates, it
does not control" is architectural). Policy distribution is a later phase.

## What this does NOT claim or cover

- **No mTLS / agent identity yet** (T-017). The control plane accepts telemetry from any connected
  agent for now; authenticated, revocable per-agent identity is a separate ticket, and until it
  lands the aggregate store must not be treated as attributable evidence — the agent_id is
  self-asserted. Stated, not hidden.
- **No heartbeat / dead-man's-switch yet** (T-018). This receives telemetry; detecting an agent
  that goes SILENT is the next ticket, which this unblocks.
- **The aggregate store is not tamper-evident.** It has no hash chain or forward-secure signatures
  — those are the agent ledger's. The control-plane store is a queryable copy, and a compromised
  control plane could alter it; the evidentiary record is the agent's local ledger, anchored
  externally (T-019). Conflating the two would be exactly the overclaim the project forbids.
- **It does not serve a rich query API.** It persists telemetry and offers a basic read-back
  (by agent, by event) sufficient to prove the round trip; a full fleet query surface is later.
- **It does not distribute policy, push actions, or control agents** (D14).

## Decisions

Depends on **D3/T-003** (the telemetry contracts), **D22/T-022** (the transport and its subjects),
**D24** (NATS is the agent↔control-plane boundary; core does not import it), **D10** (only the
summary crosses the boundary), and **D12/D30** (the agent ledger, which this is NOT).

Establishes a new decision: **the control-plane store is the fleet aggregate view, distinct from
and NOT carrying the agent ledger's evidentiary guarantees; it coordinates and observes, it does
not distribute policy or control agents.**
