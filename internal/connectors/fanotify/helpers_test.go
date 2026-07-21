//go:build linux

package fanotify_test

import (
	"context"
	"sync"
	"testing"

	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	dbLockOnce sync.Once
	dbLockConn *pgx.Conn
)

// clean checks Postgres availability (a bare PING — no migrate, which would race
// the other DB packages BEFORE the lock), acquires the shared advisory lock
// (parallel-package isolation), and drops all tables so the ledger migrates
// fresh under the held lock. Returns false (skip) if Postgres is unavailable.
func clean(t *testing.T) bool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("POSTGRES REQUIRED: %v", err)
		}
		return false
	}
	pool.Close()
	dbLockOnce.Do(func() {
		conn, cerr := pgx.Connect(ctx, dsn)
		if cerr != nil {
			t.Fatalf("lock connection: %v", cerr)
		}
		if _, cerr := conn.Exec(ctx, `SELECT pg_advisory_lock(920431)`); cerr != nil {
			t.Fatalf("advisory lock: %v", cerr)
		}
		dbLockConn = conn
	})
	p2, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	_, _ = p2.Exec(ctx,
		`DROP TABLE IF EXISTS investigation_views, agent_identities, enrollment_tokens, fleet_telemetry, peer_alerts, audit_entries, key_epochs, anchors, schema_migrations CASCADE`)
	return true
}
