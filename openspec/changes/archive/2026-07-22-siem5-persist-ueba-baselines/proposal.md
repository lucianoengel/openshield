## Why

The peer-UEBA analyzer's baseline (per-subject decayed activity) is fully in-memory.
A control-plane restart or deploy loses it and cold-starts, so for roughly one decay
half-life after every restart the analyzer has no baseline and fires NO peer anomalies —
a silent detection gap exactly when a deploy or crash might accompany an incident.

## What Changes

- `peerueba`: add `SubjectState{Subject, Count, Last}`, `Analyzer.Snapshot()` (a
  serializable per-subject view under lock), and a `WithSnapshot([]SubjectState)`
  option that seeds `New()` with prior state. Restore is EXACT because decay is computed
  forward from `Last` at query time — a restored analyzer computes the same risk.
- Migration `019_ueba_baselines.sql`: a `ueba_baselines` table (the 017 default-privilege
  grant already covers it for the non-owner writer role). Bump the migration-count test.
- `controlplane`: `PersistBaselines(ctx)` UPSERTs the snapshot; `loadBaselines(ctx)`
  reads it back; `EnablePeerUEBA` loads persisted baselines and seeds the analyzer
  (best-effort — a load failure logs and cold-starts, never blocks enable).
- `cmd/openshield-server`: schedule periodic `PersistBaselines` and persist once on
  graceful shutdown, only when peer-UEBA is enabled.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `peer-ueba`: the analyzer can snapshot and restore its baseline exactly.
- `control-plane`: peer-UEBA baselines are persisted and reloaded across restarts.

## Impact

- `internal/analytics/peerueba/` — `SubjectState`, `Snapshot`, `WithSnapshot`.
- `internal/store/postgres/migrations/019_ueba_baselines.sql` + migration-count test.
- `internal/controlplane/` — persist/load; `EnablePeerUEBA` reload.
- `cmd/openshield-server/main.go` — periodic + shutdown persistence.
- No core/proto change. Scope is the M "persist" half of SIEM-5; broadening the
  analyzer's FEATURES (per-kind / time-of-day / volume) is the separate L half, not here.
