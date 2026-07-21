//go:build linux

package fanotify_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

var (
	dbLockOnce sync.Once
	dbLockConn *pgx.Conn
)

// clean acquires the shared DB advisory lock (parallel-package isolation) and
// drops all tables so the ledger migrates fresh.
func clean(t *testing.T) {
	t.Helper()
	dbLockOnce.Do(func() {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatalf("lock connection: %v", err)
		}
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(920431)`); err != nil {
			t.Fatalf("advisory lock: %v", err)
		}
		dbLockConn = conn
	})
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, _ = pool.Exec(context.Background(),
		`DROP TABLE IF EXISTS investigation_views, agent_identities, enrollment_tokens, fleet_telemetry, audit_entries, key_epochs, anchors, schema_migrations CASCADE`)
	_ = postgres.Migrate // keep import; Open migrates
}
