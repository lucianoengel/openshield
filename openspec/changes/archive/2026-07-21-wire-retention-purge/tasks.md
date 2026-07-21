# Tasks — wire retention purge (D81)

## 1. Fleet-aggregate purge

- [x] 1.1 `controlplane.Server.PurgeOlderThan(ctx, cutoff time.Time) (int64, error)` — DELETE FROM fleet_telemetry WHERE received_at < cutoff; DELETE FROM peer_alerts WHERE detected_at < cutoff; return total rows.

## 2. Shared scheduler

- [x] 2.1 `internal/retain.Loop(ctx, interval time.Duration, fn func(context.Context))` — tick every interval, invoke fn, return on ctx cancellation.

## 3. Wire the three binaries

- [x] 3.1 `cmd/openshield-server`: retain.Loop calling PurgeOlderThan(now - OPENSHIELD_FLEET_RETENTION [90d]) every OPENSHIELD_RETENTION_INTERVAL [24h]; log rows purged.
- [x] 3.2 `cmd/openshield-engine` + `cmd/openshield-gateway`: retain.Loop calling ledger.Purge(ctx, now) on the same interval; log rows tombstoned.

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test** (real Postgres): insert fleet_telemetry + peer_alerts rows with OLD and RECENT timestamps; PurgeOlderThan(cutoff between them); assert OLD rows gone and RECENT rows remain, both tables.
- [x] 4.2 The local Ledger.Purge tombstoning is already covered by the existing postgres_test (noted, not duplicated).

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D81: retention purge scheduled and running — aggregate hard-DELETEd past a window (derived view, D38), ledger TOMBSTONED past retention (evidentiary, D36); shared retain.Loop; closes the D20 contradiction.
- [x] 5.2 `openspec validate wire-retention-purge --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| inverted cutoff comparison (`>` instead of `<`) | `TestPurgeOlderThanEnforcesWindow` |
| skip purging peer_alerts | `TestPurgeOlderThanEnforcesWindow` (wrong total) |

THE VERDICT (D81): retention purge runs on a timer — the fleet aggregate hard-DELETEd past a
configurable window (derived view, D38), the local ledger TOMBSTONED past retention (evidentiary, D36),
via a shared retain.Loop in server/engine/gateway. Closes the D20 firm-decision contradiction:
indefinite retention of personal-adjacent telemetry. NOT in scope: per-purpose retention; legal-hold
surface; changing ledger tombstoning.
