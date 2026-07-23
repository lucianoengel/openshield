## Why

SIEM-12 (D172) gave notification idempotency a DETERMINISTIC id and a server-side dedup set, so an
agent re-sending telemetry → server re-detecting → re-emitting pages exactly ONCE. But that dedup set
is **in-process memory** (`dedupeSet`), so it is LOST on restart: a server that delivered alert N,
restarts (deploy, crash, failover), and re-detects the same alert in the same window will page AGAIN —
a double-page across restarts. This is the deferred R34-13 item ("SIEM-12 dedup is per-process memory;
`dedup_key` exists — make it durable"). Deploys and HA failover are routine, so this is a real
operator-visible annoyance that undermines the "page exactly once" guarantee the feature promises.

## What Changes

- **A durable dedup table** (`notify_dedupe`): the deterministic notification id + when it was emitted.
- **`emit` checks durably**: after the fast in-memory pre-check, `emit` records the id via
  `INSERT ... ON CONFLICT (id) DO NOTHING`; a zero-row result means the id was ALREADY emitted (this
  process OR a prior one before a restart) → the alert is suppressed and counted. So a re-detected
  alert pages exactly once ACROSS restarts, not just within a process lifetime.
- **Fail-open on a DB error / no pool**: the durable layer is additive. If the DB is unreachable (or a
  test builds a pool-less Server), `emit` falls back to the in-memory decision and still pages — a
  MISSED page (security gap) is worse than a rare double-page during a DB outage.
- **Retention prune**: a `PruneNotifyDedupe(before)` deletes ids older than the dedup window, wired
  into the existing leader retention loop, so the table stays bounded.

The in-memory `dedupeSet` stays as a fast pre-filter (no DB hit for an obvious same-process duplicate);
the DB is the cross-restart authority.

## Capabilities

### New Capabilities
- `durable-notification-dedup`: persisting delivered notification ids so the "page exactly once"
  idempotency survives a restart/failover, fail-open on a database outage.

### Modified Capabilities
<!-- none: this hardens the existing SIEM-12 dedup; no other capability's requirements change. -->

## Impact

- `internal/store/postgres`: migration `023_notify_dedupe.sql` (auto-grants to the writer role via 017).
- `internal/controlplane`: `emit` gains a durable check; `markNotifyDurable(ctx,id)` +
  `PruneNotifyDedupe(ctx,before)`; a nil pool / DB error falls back to in-memory (fail-open).
- `cmd/openshield-server`: prune the dedup table on the retention loop.
- `internal/store/postgres/postgres_test.go`: migration count 22 → 23.
- No proto change, no core change, no new dependency.
