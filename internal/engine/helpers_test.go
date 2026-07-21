package engine_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucianoengel/openshield/internal/core"
)

// dbLock serializes DB-mutating tests across parallel packages sharing this
// database (see internal/store/postgres for the rationale). Same lock key.
var (
	dbLockOnce sync.Once
	dbLockConn *pgx.Conn
)

func lockDB(t *testing.T) {
	t.Helper()
	dbLockOnce.Do(func() {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatalf("lock connection: %v", err)
		}
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(920431)`); err != nil {
			t.Fatalf("acquiring advisory lock: %v", err)
		}
		dbLockConn = conn
	})
}

type stageFn struct {
	name string
	fn   func(context.Context, *core.State) (core.Outcome, error)
}

func (s stageFn) Name() string { return s.name }
func (s stageFn) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	return s.fn(ctx, st)
}
func stageFunc(name string, fn func(context.Context, *core.State) (core.Outcome, error)) core.Stage {
	return stageFn{name, fn}
}

func mustPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
