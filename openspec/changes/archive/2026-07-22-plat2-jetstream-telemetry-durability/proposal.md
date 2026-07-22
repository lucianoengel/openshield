## Why

Telemetry ingest is at-most-once. The publisher sends over core NATS (`conn.Publish`), and the control
plane subscribes with a plain callback. SEC-4 (D116) made a slow-consumer drop OBSERVABLE (pending
limits + an ErrorHandler that counts `DroppedMessages`), but it does not PREVENT loss — under
sustained overload, or a control-plane restart mid-stream, verified telemetry vanishes with only a
counter to show for it. The agent spool covers a broker-UNREACHABLE outage, but not a
broker-reachable / consumer-slow-or-restarting window. ADR-2: move telemetry to durable JetStream
consumers with explicit ack, which removes the drop window entirely — the message persists in the
stream until the control plane has actually persisted it. Pair it with replacing the per-message
`FOR UPDATE` that hard-serializes ingest.

## What Changes

- A JetStream **stream** over the single signed-telemetry subject (`SubjectSigned`), file-backed so it
  survives a broker/consumer restart, **WorkQueue** retention (a delivery bus that drops a message
  once the single consumer acks) — the hash-chained ledger stays the system-of-record; the stream is
  NOT evidence (D12). Created idempotently by the control plane on connect.
- The publisher publishes via JetStream (`js.Publish`, checking the `PubAck`); the existing spool
  stays the pre-broker buffer (a JetStream publish error still spools, unchanged flow).
- A **durable, explicit-ack** consumer delivers to `handleSigned`, which **acks only after a
  successful persist**, **naks** a transient DB error (redelivery), and **acks-as-terminal + counts** a
  permanent failure (bad signature / unknown / revoked / a redelivered-already-applied message that
  verifies as `ErrReplay`, which must be acked or it redelivers forever).
- `VerifySigned` replaces `SELECT … FOR UPDATE` with a per-agent `pg_advisory_xact_lock` so the
  monotonic-sequence check stays serialized per agent without holding the identity row lock across the
  whole transaction (always-on, independent of the transport mode).
- **Scope:** durable ingest is **env-gated** (`OPENSHIELD_JETSTREAM`) — enabled, the publisher and
  subscriber use the durable path; disabled, the current core-NATS path is unchanged (existing tests
  stay valid). Flipping the default to JetStream-always and migrating the full telemetry test suite is
  a NOTED follow-on. The risk/posture channels stay core NATS (best-effort signals, not the durable
  telemetry path).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `event-transport`: signed telemetry can be delivered over a durable JetStream stream with
  at-least-once, explicit-ack semantics (when enabled), documented honestly alongside the default
  core-NATS at-most-once mode; the stream is a delivery bus, never the evidence store.
- `control-plane`: durable telemetry ingest acknowledges a message only after it is persisted (or
  terminally rejected), so a consumer restart or slow persist does not lose verified telemetry; the
  per-message verify serializes per agent via an advisory lock rather than an identity-row `FOR UPDATE`.

## Impact

- **Code:** `internal/transport/nats` (JetStream publish path + stream/consumer helpers, env-gated),
  `internal/controlplane` (durable-ack subscribe + ack/nak logic in `handleSigned`; advisory-lock in
  `VerifySigned`), `cmd/openshield-server`/`fleet-agent` wiring (env), and tests (an embedded NATS with
  JetStream enabled).
- **No proto/core change.** D12 preserved: the stream is not the record. Backward compatible: with the
  env off, behavior is exactly today's.
