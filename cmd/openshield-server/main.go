// Command openshield-server is the control plane (T-023).
//
// It subscribes to the agent telemetry subjects over NATS and persists what it
// receives to the fleet aggregate store. It coordinates and observes; it does
// NOT distribute policy or control agents (D14). The evidentiary record is the
// agent's local forward-secure ledger, NOT this aggregate.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

func main() {
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	natsURL := env("OPENSHIELD_NATS_URL", "nats://127.0.0.1:4222")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fatal("connecting to Postgres: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fatal("Postgres unreachable: %v", err)
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		fatal("migrating: %v", err)
	}

	srv := controlplane.New(pool)
	fmt.Fprintf(os.Stderr, "openshield-server: subscribing to telemetry on %s\n", natsURL)
	if err := srv.Run(ctx, natsURL); err != nil && ctx.Err() == nil {
		fatal("control plane: %v", err)
	}
	fmt.Fprintln(os.Stderr, "openshield-server: shut down")
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "openshield-server: "+format+"\n", args...)
	os.Exit(1)
}
