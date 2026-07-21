## 1. Fleet store

- [x] 1.1 Migration `005`: `fleet_telemetry(id BIGSERIAL, agent_id, kind, event_id, received_at,
      payload BYTEA)`; indexes on agent_id and event_id
- [x] 1.2 `controlplane` store methods: `insert(kind, agentID, eventID, payload)`,
      `Telemetry(agentID)`, `TelemetryForEvent(eventID)`

## 2. Subscriber

- [x] 2.1 `Server.Run(ctx, natsURL)`: connect, subscribe to the three subjects; handler decodes the
      proto for indexing (agent_id/event_id), stores the raw payload, inserts a row
- [x] 2.2 A decode failure is counted (a DecodeFailures counter) and the message dropped — never a
      silent vanish, never a stalled subscription

## 3. Tests (embedded NATS + real Postgres)

- [x] 3.1 **Test**: agent transport publishes Event + summary + Decision over an embedded NATS →
      control plane persists → read back by agent and by event. `TestTelemetryRoundTrip`
- [x] 3.2 **Test**: a stored classification carries only type+confidence+count. `TestNoContentInAggregate`
- [x] 3.3 **Test**: a malformed message increments DecodeFailures and does not stall the
      subscription. `TestMalformedIsCountedNotSilent`

## 4. Command + docs

- [x] 4.1 `cmd/openshield-server` runs the control plane (connect NATS + Postgres, Run until ctx)
- [x] 4.2 Note in `docs/decisions.md` (new D-number): the aggregate store is the fleet view, NOT
      the evidentiary ledger; agent_id self-asserted until T-017; observes/coordinates, no policy
      distribution or control (D14)
- [x] 4.3 Mark T-023 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| decode failure swallowed instead of counted | `TestMalformedIsCountedNotSilent` |
| wrong event_id persisted (read-back misses) | `TestTelemetryRoundTrip` |

The full acceptance runs end to end over an EMBEDDED nats-server + real Postgres:
an agent `nats.Transport` publishes an Event + ClassificationSummary + Decision,
the control plane persists them, and read-back by agent and by event returns all
three (`TestTelemetryRoundTrip`). A stored classification decodes as a
ClassificationSummary with exactly its four boundary-safe fields — content cannot
have arrived because the transport has no LocalClassification method
(`TestNoContentInAggregate`). A malformed message increments `DecodeFailures` and
the subscription keeps working. `cmd/openshield-server` runs it against real NATS
+ Postgres. Wired into the ledger CI job (Postgres service + embedded NATS).
