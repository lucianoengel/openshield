## Context

`internal/transport/nats` publishes to `SubjectEvents/SubjectClassification/SubjectDecisions` as
marshalled proto. `internal/store/postgres` holds the agent's forward-secure ledger. core must not
import a broker (D24), so the control plane lives in `internal/controlplane` and imports the NATS
client itself. nats-server is embeddable, so the round trip is fully testable.

## Goals / Non-Goals

**Goals:**
- Subscribe to the three telemetry subjects, decode, and persist to a fleet store.
- Prove the round trip end to end over an embedded NATS: agent publishes → persisted → read back.
- Keep the fleet store distinct from the agent ledger, and honest about not carrying its
  guarantees.

**Non-Goals:**
- mTLS/identity (T-017), heartbeat (T-018), policy distribution, a rich query API, tamper-evidence
  on the aggregate.

## Decisions

### A `fleet_telemetry` table, kind-tagged
Migration `005`: `fleet_telemetry(id BIGSERIAL, agent_id TEXT, kind TEXT, event_id TEXT,
received_at TIMESTAMPTZ, payload BYTEA)`. `payload` is the raw proto so no fidelity is lost and a
schema change to a contract does not require a migration here. `kind` ∈ {event, classification,
decision}. Indexed by (agent_id) and (event_id) for read-back.

### Server subscribes and persists
`controlplane.Server{ pool, sub[] }`. `Run(ctx, natsURL)` connects, subscribes to the three
subjects with a handler that decodes the proto (only to extract agent_id/event_id for indexing —
the payload is stored raw) and inserts a row. A decode failure is logged and the message dropped
with a recorded reason (a malformed message must not stall the subscription, but must not vanish
silently either — it is counted).

The subscription is a plain NATS subscription (not JetStream) for Phase 1: the agent's durable
queue (T-024) is the delivery guarantee on the agent side, and at-least-once fleet delivery is a
later concern. Stated so the choice is deliberate.

### Only the summary can arrive
The transport has no LocalClassification method, so the classifications subject carries only
`ClassificationSummary`. The control plane decodes that type; there is no path by which content
could be received. A test decodes a summary and asserts the stored/queried shape is
type+confidence+count only.

### Read-back
`Telemetry(ctx, agentID)` and `TelemetryForEvent(ctx, eventID)` return stored rows. Enough to prove
"telemetry lands in Postgres, CLI reads it back"; a full query surface is later.

### End-to-end test with embedded NATS
Start an in-process nats-server, point an agent `nats.Transport` and the control plane at it,
publish an Event + summary + Decision, wait for the subscription to persist, and assert read-back.
A helper waits on a condition with a timeout rather than a fixed sleep.

## Risks / Trade-offs

- **agent_id is self-asserted until T-017.** The store must not be treated as attributable evidence
  yet; stated in the proposal and the docs. The evidentiary record is the agent ledger.
- **Plain NATS, not JetStream, for the subscription.** At-least-once fleet delivery is deferred; the
  agent-side durable queue (T-024) is the delivery guarantee that matters for not losing evidence.
- **Storing raw payload bytes** trades queryability for fidelity and migration-freedom; the decoded
  index columns (agent_id, event_id) cover the read paths Phase 1 needs.
- **The aggregate is not tamper-evident.** By design; the agent ledger is. Documented so the two are
  never conflated.
