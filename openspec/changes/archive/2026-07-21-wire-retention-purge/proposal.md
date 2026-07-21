## Why

D20 declares "enforced retention with automatic purge" a firm Phase-1 commitment, but
`Ledger.Purge` (the forward-secure ledger's retention tombstoning, T-013) has ZERO
production callers, and the fleet aggregate (`fleet_telemetry`, `peer_alerts`) has no
retention at all. As deployed, OpenShield retains personal-adjacent telemetry
INDEFINITELY — the exact posture its GDPR reasoning forbids. This schedules the purge.

## What Changes

- `controlplane.Server.PurgeOlderThan(ctx, cutoff)` — hard-DELETE `fleet_telemetry`
  (by `received_at`) and `peer_alerts` (by `detected_at`) older than the cutoff,
  returning rows removed. The fleet aggregate is a DERIVED view, not the evidentiary
  ledger (D38), so a hard delete is correct here.
- `internal/retain.Loop(ctx, interval, fn)` — a shared ticker that invokes `fn` until
  the context is cancelled, so the three binaries don't duplicate the loop.
- `cmd/openshield-server` schedules `PurgeOlderThan(now - OPENSHIELD_FLEET_RETENTION,
  default 90d)` every `OPENSHIELD_RETENTION_INTERVAL` (default 24h), logging rows
  purged.
- `cmd/openshield-engine` and `cmd/openshield-gateway` schedule `ledger.Purge(now)` on
  the same interval — finally running the tombstoning D20 promised (content erased,
  hash chain still verifiable, D36).

## Capabilities

### Modified Capabilities
- `privacy-features`: automatic retention purge is scheduled and enforced (the local
  ledger tombstones past-retention content on a timer).
- `control-plane`: the fleet aggregate has an enforced retention window (hard-deleted
  past a configurable age).

## Impact

- New `Server.PurgeOlderThan`, `internal/retain`; scheduling in three binaries;
  `docs/decisions.md` D81. Reuses the existing tested `Ledger.Purge`.
- Proven against real Postgres: old fleet_telemetry/peer_alerts rows are purged past
  the cutoff, recent rows remain.
- NOT in scope (stated): per-subject/per-purpose retention; a legal-hold exemption;
  changing the ledger's class-based tombstoning. Respects D20, D36, D38, D30.
