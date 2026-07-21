## Context

`Ledger.Purge(ctx, now)` (postgres) TOMBSTONES bounded-class entries past their age —
erases content, keeps the chain skeleton verifiable (D36) — but nothing calls it. The
fleet aggregate (`fleet_telemetry.received_at`, `peer_alerts.detected_at`) grows
unboundedly. The distinction that matters: the local ledger is the evidentiary system
of record (tombstone, never delete, D30/D38); the fleet aggregate is a derived
detection view (safe to hard-delete).

## Goals / Non-Goals

**Goals:** run the retention purge that D20 promised, on both the ledger (tombstone)
and the fleet aggregate (delete); one shared scheduler.

**Non-Goals:** per-subject/per-purpose retention; legal-hold; changing the ledger's
class-based tombstoning semantics.

## Decisions

**Tombstone the ledger, hard-delete the aggregate — because they are different kinds
of record.** The forward-secure ledger is evidence; erasing a row outright would break
the hash chain and destroy the ability to prove nothing was suppressed, so its purge
TOMBSTONES (content gone, links/signature kept, D36) — already implemented in
`Ledger.Purge`. The fleet aggregate is a derived, re-derivable detection surface (D38),
not evidence, so its purge is a plain `DELETE` past a window. Using the wrong mechanism
on either would be a bug: deleting from the ledger destroys verifiability; tombstoning
the aggregate is pointless ceremony.

**One shared `retain.Loop`, three schedulers.** The engine and gateway own a local
ledger; the server owns the aggregate. Each needs the same "every N, purge, log" loop,
so `retain.Loop(ctx, interval, fn)` centralises the ticker (cancellation-aware) and
each binary supplies its own purge closure. A purge is logged (rows affected) — an
operational event, not silent.

**Configurable window, sane defaults.** `OPENSHIELD_FLEET_RETENTION` (default 90d) and
`OPENSHIELD_RETENTION_INTERVAL` (default 24h). The ledger's per-class ages are already
defined in `RetentionClass.MaxAge` (D36); the timer just runs the purge that consults
them.

## Risks / Trade-offs

- **A single fleet window is coarse.** Per-purpose retention (DLP vs insider-risk) is a
  finer control a real deployment may need; noted, not built. One window is the honest
  Phase-1 step from "infinite" to "bounded."
- **Purge runs on every binary that owns a store.** Two engines sharing one database
  would both run the ledger purge; idempotent (tombstoning an already-tombstoned row is
  a no-op via the `WHERE tombstoned_at IS NULL` guard), so it is safe if wasteful.
- **No legal-hold exemption** — a held investigation class already has no cutoff
  (`RetentionInvestigation` is unbounded by construction), which is the coarse hold
  mechanism; a per-case hold surface is a noted follow-up.
