## 1. The Leader primitive

- [x] 1.1 `internal/controlplane/leader.go`: `Leader{pool, key, poll}` + `NewLeader(pool)`.
      `acquire(ctx)` acquires a pool connection and polls `pg_try_advisory_lock(key)` until it wins
      (holding that connection) or ctx is done; a non-winning attempt releases the connection and waits
      one poll interval.
- [x] 1.2 `Run(ctx, onElected func(leaderCtx context.Context)) error`: loop while ctx is live — acquire,
      derive `leaderCtx = WithCancel(ctx)`, start a watcher that pings the held connection and cancels
      `leaderCtx` on failure (lease lost), call `onElected(leaderCtx)`, then `pg_advisory_unlock(key)` +
      release the connection, and loop to re-acquire.

## 2. Gate the singleton work in the cmd

- [x] 2.1 `cmd/openshield-server/main.go`: build a `Leader` and run the singleton work — the retain
      loops (purge/overdue/persist), `EnablePeerUEBA`, and `srv.Run` — inside `onElected(leaderCtx)`,
      using `leaderCtx` instead of the process ctx for those; a standby waits in `Leader.Run`. Preserve
      the final graceful `PersistBaselines` on shutdown.

## 3. Verify + mutation guards

- [x] 3.1 Real-PG test: two `Leader`s (separate pools to the same DB, same key). Exactly ONE calls
      `onElected` while the other blocks (assert the second is NOT elected within a bound). Then cancel
      the leader's ctx (graceful step-down) → assert the standby is subsequently elected (failover).
- [x] 3.2 Test: a single Leader is elected immediately (the non-HA case) and its `leaderCtx` cancels
      when the process ctx is cancelled.
- [x] 3.3 Mutation guards (apply, FAIL, revert): (A) `pg_try_advisory_lock` → a no-op that always
      reports leader → the "exactly one leader / standby blocks" assertion FAILs (split-brain);
      (B) skip the explicit `pg_advisory_unlock` on step-down → the failover (standby-elected-after-release)
      assertion FAILs (the lock lingers on the pooled connection). Record it.

## 4. Gate + record

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 4.2 decisions.md entry (next D-number); note Postgres HA + client routing are ops (deferred).
- [x] 4.3 Roadmap + memory updated.
