package controlplane

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// leaderLockKey is the Postgres advisory-lock key that names control-plane leadership (PLAT-2b). A
// fixed constant so every instance contends for the SAME lock; any distinct 64-bit value works.
const leaderLockKey int64 = 0x051EADE7 // "leader"

// defaultLeaderPoll is how often a standby retries acquiring leadership, and how often the leader pings
// its held connection to detect a lost lease. Small enough for prompt failover, large enough not to
// hammer the database.
const defaultLeaderPoll = 3 * time.Second

// Leader elects exactly one active control-plane instance via a Postgres SESSION-scoped advisory lock
// (PLAT-2b/ADR-3). The lock is held on a DEDICATED connection for the whole leadership: at most one
// connection can hold it (the single-leader guarantee is the database's, not ours), and if the leader
// process or its connection dies Postgres releases the lock automatically — the connection liveness IS
// the lease, so failover needs no TTL, heartbeat, or clock.
type Leader struct {
	pool *pgxpool.Pool
	key  int64
	poll time.Duration
}

// NewLeader builds a leader elector over pool.
func NewLeader(pool *pgxpool.Pool) *Leader {
	return &Leader{pool: pool, key: leaderLockKey, poll: defaultLeaderPoll}
}

// Run blocks: it repeatedly acquires leadership and, while it holds it, calls onElected with a context
// cancelled when leadership is lost (the held connection dies) or ctx is done; then it releases the
// lock and loops to re-acquire — a standby taking over. It returns when ctx is done. A single deployed
// instance wins immediately and never yields, so it behaves exactly as a non-HA deployment.
func (l *Leader) Run(ctx context.Context, onElected func(leaderCtx context.Context)) error {
	for ctx.Err() == nil {
		conn, err := l.acquire(ctx)
		if err != nil {
			return err // ctx done or an unexpected database error
		}
		if conn == nil {
			return ctx.Err()
		}
		leaderCtx, cancel := context.WithCancel(ctx)
		held := make(chan struct{})
		go func() { l.hold(leaderCtx, cancel, conn); close(held) }()
		onElected(leaderCtx) // runs the singleton work; returns when leaderCtx is cancelled
		cancel()
		<-held // the watcher must stop touching the connection before we release it (pgx conns are not concurrent-safe)
		l.release(conn)
	}
	return ctx.Err()
}

// acquire polls pg_try_advisory_lock until this instance wins the lock (returning the connection that
// now HOLDS it — the caller must keep it until step-down) or ctx is done. A non-winning attempt
// releases its connection and waits one poll interval so a standby does not busy-loop.
func (l *Leader) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	for ctx.Err() == nil {
		conn, err := l.pool.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&got); err != nil {
			conn.Release()
			return nil, err
		}
		if got {
			return conn, nil // elected — hold this connection (and its session lock)
		}
		conn.Release() // someone else is leader; retry after the poll interval
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(l.poll):
		}
	}
	return nil, ctx.Err()
}

// hold watches the leader's connection: if a ping fails (the connection died — a lost lease) it cancels
// leaderCtx so the singleton work stops and Run loops to re-acquire.
func (l *Leader) hold(ctx context.Context, cancel context.CancelFunc, conn *pgxpool.Conn) {
	t := time.NewTicker(l.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := conn.Ping(ctx); err != nil {
				cancel()
				return
			}
		}
	}
}

// release relinquishes leadership. A pgxpool connection returned to the pool is NOT closed and a
// session advisory lock is NOT dropped by Release(), so a graceful step-down MUST unlock explicitly —
// otherwise the lock lingers on the pooled connection and a standby can never take over. (A crashed
// connection closes and Postgres releases the lock; this handles the graceful path.)
func (l *Leader) release(conn *pgxpool.Conn) {
	uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, l.key)
	conn.Release()
}
