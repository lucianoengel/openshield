package engine_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucianoengel/openshield/internal/core"
)

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
