## Why

The control plane is a singleton. It holds in-memory state — the peer-UEBA analyzer, the notify dedup
set, per-subject alert cooldowns — and runs singleton work: the telemetry consumer and the periodic
purge/overdue/persist loops. SIEM-5 made the baseline durable but not multi-writer-safe, and PLAT-2's
durable JetStream ingest makes a takeover lossless — but there is still no way to run a hot standby
without two instances both consuming and both mutating their own analyzer. ADR-3: active-passive HA
via a Postgres leader lease, decided now before more in-memory state accretes.

## What Changes

- A `Leader` primitive: an instance holds ONE dedicated Postgres connection and takes a **session**
  advisory lock (`pg_try_advisory_lock`). At most one instance holds it (no split-brain); if the
  leader process/connection dies the lock **auto-releases** (the connection liveness IS the lease —
  no TTL table or heartbeat), so a standby's next attempt wins and it takes over.
- `Leader.Run(ctx, onElected)` blocks until elected, then runs `onElected(leaderCtx)` with a context
  cancelled when leadership is lost; a standby polls until it can acquire; on loss it loops to
  re-acquire.
- `cmd/openshield-server` runs the singleton work — the telemetry `Subscribe`, `EnablePeerUEBA`, and
  the retain loops — INSIDE `leaderCtx`, so only the leader does it and a standby waits. A new leader
  reloads the peer-UEBA baseline from Postgres (SIEM-5), so analytics resume; the notify dedup set and
  cooldowns are per-instance and reset on failover (a brief window of a possible duplicate page —
  acceptable, noted).
- `Server.Run` is NOT gated internally (existing tests call it directly, unchanged) — the leader-gating
  lives in the cmd plus the testable `Leader` primitive.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `control-plane`: the singleton work runs under an active-passive leader lease — at most one instance
  is leader at a time, and a standby takes over when the leader releases or dies.

## Impact

- **Code:** `internal/controlplane/leader.go` (the `Leader` primitive), `cmd/openshield-server/main.go`
  (run the singleton work inside `leaderCtx`), and tests.
- **No proto/core change.** Backward compatible: a single deployed instance simply becomes leader
  immediately and behaves exactly as today.
- **Deferred (ADR-3):** stateless-horizontal scaling; Postgres HA itself (DB replication/failover is
  an ops concern); a VIP/load-balancer to route clients to the current leader (ops).
