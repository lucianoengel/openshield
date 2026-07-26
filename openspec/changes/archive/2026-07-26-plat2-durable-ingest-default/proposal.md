## Why

"Durable ingest" is a claim the code does not currently deliver for production, and the reason is not the
default flag — it is a wiring gap.

`SignedPublisher.UseJetStream()` exists, and the control plane's durable explicit-ack consumer is wired
behind `OPENSHIELD_JETSTREAM`. But **the only caller of `UseJetStream()` is `cmd/openshield-fleet-agent`,
the simulator.** `cmd/openshield-engine` (DLP/HIPS detections) and `cmd/openshield-gateway` (network and ZT
decisions) build a publisher and never switch it, so even with the env var set their telemetry publishes
over core NATS, at-most-once. A control-plane restart mid-backlog loses real detections today; only the
simulator's traffic is durable.

That is the substance of this ticket. Flipping the default is the smaller half.

## What Changes

- **Durable ingest becomes the default.** `natsx.JetStreamEnabled()` inverts to opt-**out**
  (`OPENSHIELD_JETSTREAM=0|false|off`). One helper keeps producers and the consumer from ever disagreeing
  about which mode they are in.
- **The real producers are wired.** `UseJetStream()` is called in the engine and the gateway at the same
  point the fleet-agent does — right after the publisher is built, before the spool is attached — so all
  three producers behave identically.
- **Unavailable JetStream fails fast.** If the broker has no JetStream, or the stream cannot be ensured, the
  process exits with an error naming the opt-out. It does **not** fall back to core NATS: silently
  downgrading durability would recreate the exact missing-evidence failure this ticket removes, and it
  would do so invisibly.
- **Everything around it stays as it is.** The agent spool remains the pre-broker buffer in both modes
  (D40/D67), and the hash-chained ledger remains the system of record — JetStream is a bus, never the audit
  store (ADR-2/D12).

**BREAKING for a deployment on a JetStream-less broker:** such a deployment must either enable JetStream on
the broker or set `OPENSHIELD_JETSTREAM=0`. The failure is loud and names the fix; the upgrade note belongs
in PLAT-9's runbook.

## Capabilities

### Modified Capabilities

- `event-transport`: the default delivery mode becomes durable at-least-once JetStream rather than core-NATS
  at-most-once; every real producer (not only the simulator) publishes into the stream; and an unavailable
  JetStream is a startup failure rather than a silent downgrade.

## Impact

- **Code:** `internal/transport/nats/jetstream.go` (the gate inverts), `cmd/openshield-engine`,
  `cmd/openshield-gateway`, `cmd/openshield-fleet-agent` (all three switch the publisher and fail fast
  identically). The control-plane consumer is unchanged — it already reads the same helper.
- **Decisions:** implements **ADR-2** (JetStream is a bus, Postgres/the ledger is the system of record) and
  depends on **D30/D12** (the aggregate and the stream are not evidence), **D40/D67** (the spool is the
  pre-broker durability), and **R34-4** (the consumer's Nak-with-backoff, which is what makes at-least-once
  survivable rather than a hot loop). No proto change, no migration, no new dependency.
- **Operational:** a JetStream-enabled broker becomes a requirement unless opted out. The dev compose stack
  and any deployment manifest need JetStream enabled on the NATS server.

### What this change does NOT claim or cover

- **It does not make telemetry lossless.** A message the producer never managed to publish and never
  spooled is still gone. An operator who opts out is back to at-most-once. And the stream's own limits
  (which exist so a permanently-down consumer cannot fill the disk) mean a long enough outage still drops —
  bounded durability is not unbounded durability.
- **It does not add exactly-once.** Redelivery means at-least-once; the ingest is idempotent by verified
  sequence, not deduplicated by the broker.
- It does **not** change the ledger's role: stream retention is never evidence.
- It does **not** touch the other NATS subjects. The events/classification/decision fanout, risk, posture
  and attestation subjects stay core-NATS best-effort by design — they are coordination, not the
  attributable telemetry record.
- It does **not** address JetStream clustering, HA topology, mirroring, or how the broker gets deployed —
  that is PLAT-6/PLAT-9.
