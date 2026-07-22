## Context

`cmd/openshield-server` starts the singleton work on the process context: the retain loops (purge,
overdue, persist), `EnablePeerUEBA` (the in-memory analyzer), and `srv.Run` (the telemetry consumer).
Two instances would both consume and both mutate their own analyzer — not safe. ADR-3 chooses
active-passive: exactly one leader runs the singleton work; a standby waits.

## Goals / Non-Goals

**Goals:**
- Exactly one leader at a time (no split-brain), with automatic takeover on leader failure.
- Gate the singleton work on leadership without touching `Server.Run` (existing tests unchanged).
- Testable with real Postgres (two instances contend; failover works).

**Non-Goals:**
- Stateless-horizontal scaling; Postgres HA itself (ops); a client-routing VIP (ops).
- Making the analyzer multi-writer (active-passive means single-writer by construction).

## Decisions

### D-a · Leader lease = a Postgres SESSION advisory lock on a dedicated connection
`Leader` acquires ONE connection from the pool and calls `pg_try_advisory_lock(key)` on it. The lock is
SESSION-scoped, so at most one connection holds it — the exactly-one-leader guarantee is the database's,
not ours. If the leader process or its connection dies, Postgres releases the session lock
automatically (the connection liveness IS the lease), so a standby's next `pg_try_advisory_lock` wins —
failover with no TTL table, heartbeat, or clock to get wrong.

*Alternative considered:* a `leaders` table with a TTL and a heartbeat. **Rejected** — a TTL needs a
clock and a renew loop and races on expiry; a session lock has none of that and fails over exactly when
the connection drops.

### D-b · The pgxpool release gotcha — unlock explicitly on graceful step-down
A pgxpool connection returned to the pool is NOT closed, and a session advisory lock is NOT released by
`Release()` — it lingers on the pooled connection. So on a GRACEFUL step-down the `Leader` MUST
`pg_advisory_unlock(key)` before releasing the connection; on a crash the connection actually closes and
Postgres releases the lock. The `Leader` holds the connection for the whole leadership and unlocks on
exit.

### D-c · Run(ctx, onElected) with a leadership-scoped context
`Leader.Run` loops while `ctx` is live: it polls (acquire) until it wins the lock, derives
`leaderCtx = WithCancel(ctx)`, starts a watcher that pings the held connection and cancels `leaderCtx`
if the ping fails (lease lost), calls `onElected(leaderCtx)` (which runs the singleton work and returns
when `leaderCtx` is cancelled), then unlocks + releases and loops to re-acquire (a re-election). A
single deployed instance wins immediately and never yields — behaviorally identical to today.

### D-d · The cmd runs the singleton work inside leaderCtx; the standby waits
`cmd/openshield-server` wraps the retain loops, `EnablePeerUEBA`, and `srv.Run` in `onElected`, using
`leaderCtx`. A standby is blocked in `Leader.Run` acquiring — it serves nothing (active-passive; a VIP
routes clients to the active, ops). On takeover the new leader reloads the durable baseline
(`EnablePeerUEBA` → SIEM-5) and resumes the durable JetStream consumer (PLAT-2) with no telemetry loss.

## Risks / Trade-offs

- **A lingering lock if step-down forgets to unlock** → D-b unlocks explicitly on graceful exit; the
  crash path auto-releases. Tested: after a leader steps down, a standby is elected.
- **Poll latency on failover** → a standby polls every few seconds; failover takes up to one poll
  interval. Acceptable for active-passive; tunable.
- **In-memory dedup/cooldown reset on failover** → a subject may re-page once after takeover (the alert
  is real). The durable baseline is what matters and it reloads; noted.
- **Split-brain if the lock is bypassed** → the database guarantees single-holder; a mutation that
  always reports leader is what the test's exactly-one assertion catches.

## Migration Plan

Backward compatible: deploy; a single instance becomes leader immediately (unchanged behavior). For HA,
run a second instance against the same Postgres — it stands by and takes over on leader loss. Rollback
reverts the cmd wrapping (the Leader primitive is inert if unused). No schema/proto change.

## Open Questions

None. Postgres HA and client routing are explicitly ops concerns (ADR-3).
