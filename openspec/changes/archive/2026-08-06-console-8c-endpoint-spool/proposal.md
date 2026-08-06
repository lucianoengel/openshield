# CONSOLE-8c · The endpoint's durable offline spool

## Why

`SetSpool` was called only by `cmd/openshield-fleet-agent`, the fleet SIMULATOR, and all three
spool-drain integration scenarios exercise that binary. A real endpoint therefore **dropped its telemetry
for the whole of any broker outage**, and no backfill path exists anywhere in the product.

**Being precise about the damage, because overstating it would be its own dishonesty.** The endpoint's
hash-chained ledger recorded every decision throughout (D30), so this was never EVIDENCE loss. What was
lost was the FLEET's copy — permanently. Correlation, XDR, incidents and peer-UEBA each carry a hole for
the outage window that nothing will ever fill.

`internal/engine/telemetry.go` asserted the mitigation the whole time. It justified its best-effort
publish with *"the decision is already durably recorded in the local ledger (D30) and the publisher
offline-queues (D67), so a lost telemetry copy degrades the fleet VIEW, not the audit trail."* The first
clause was true. The second was not, for this binary.

Notably the **declared configuration surface was honest** — `OPENSHIELD_QUEUE_DIR` existed on
`FleetAgentFields` and not on `EngineFields` — which is precisely why no config guard caught it.

## What Changes

- `cmd/openshield-engine` opens the queue and attaches it, with its own drain loop.
- The drain loop is **independent of the heartbeat ticker**: disabling the liveness signal must not also
  stop the spool draining.
- An endpoint with no spool **says so at startup and says what it costs** (D31).
- An eviction past the ceiling logs at ERROR — past that point the spool discards what it exists to hold.
- `OPENSHIELD_QUEUE_DIR` / `_MAX` / `_FLUSH_INTERVAL` declared on `EngineFields`.
- The false half of the `telemetry.go` claim is corrected rather than deleted, so the next reader learns
  what it depends on.

## Impact

- Affected specs: `event-transport`.
- No proto change, no migration, no behaviour change when unconfigured — except that the silence ends.
