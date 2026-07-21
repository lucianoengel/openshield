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
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

func main() {
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	// Operator-local subcommands (issuance/revocation are NOT network endpoints, D51).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "issue-token":
			os.Exit(issueToken(dsn, os.Args[2:]))
		case "revoke":
			os.Exit(revokeAgent(dsn, os.Args[2:]))
		}
	}
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

	// Server-side peer-UEBA (D54), OFF unless a threshold is configured — enabling
	// it is the operator's D23 consent/DPIA decision, never a default. It observes
	// the verified fleet stream and records peer alerts; it does not control agents.
	if v := os.Getenv("OPENSHIELD_PEER_UEBA_THRESHOLD"); v != "" {
		threshold, err := strconv.ParseFloat(v, 64)
		if err != nil {
			fatal("OPENSHIELD_PEER_UEBA_THRESHOLD=%q: %v", v, err)
		}
		cooldown := 1 * time.Hour
		if c := os.Getenv("OPENSHIELD_PEER_UEBA_COOLDOWN"); c != "" {
			if d, err := time.ParseDuration(c); err == nil {
				cooldown = d
			}
		}
		srv.EnablePeerUEBA(threshold, cooldown)
		fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA enabled (threshold %.2f, cooldown %s)\n", threshold, cooldown)
	}

	// Optional enrollment endpoint (D44 over the wire). Production fronts it with
	// TLS. Token issuance is NOT exposed — an admin-local operation.
	if addr := os.Getenv("OPENSHIELD_HTTP_ADDR"); addr != "" {
		go func() {
			fmt.Fprintf(os.Stderr, "openshield-server: enrollment endpoint on %s\n", addr)
			if err := srv.ServeHTTP(ctx, addr); err != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: enrollment endpoint: %v\n", err)
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "openshield-server: subscribing to telemetry on %s\n", natsURL)
	if err := srv.Run(ctx, natsURL); err != nil && ctx.Err() == nil {
		fatal("control plane: %v", err)
	}
	fmt.Fprintln(os.Stderr, "openshield-server: shut down")
}

func issueToken(dsn string, args []string) int {
	ttl := 3600
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil {
			ttl = v
		}
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue-token:", err)
		return 1
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		fmt.Fprintln(os.Stderr, "issue-token migrate:", err)
		return 1
	}
	tok, err := controlplane.New(pool).IssueToken(ctx, time.Duration(ttl)*time.Second, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue-token:", err)
		return 1
	}
	fmt.Println(tok)
	return 0
}

func revokeAgent(dsn string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: openshield-server revoke <agent-id>")
		return 2
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	defer pool.Close()
	if err := controlplane.New(pool).Revoke(ctx, args[0], time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "revoked %s\n", args[0])
	return 0
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
