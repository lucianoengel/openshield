// Package postgres implements the audit ledger over PostgreSQL.
//
// The interface lives in internal/core; this package holds the driver, because
// core must not depend on a database — same boundary and same reasoning as the
// transport (D24). Enforced by scripts/check-core-deps.sh.
package postgres

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrate applies pending migrations in order.
//
// Forward-only. A hash-chained ledger cannot be rolled back to an earlier
// schema without invalidating every entry written under the newer one, so
// "down" migrations would be a facility that could only be used destructively.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // numeric prefixes give a deterministic order

	for _, name := range names {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name).
			Scan(&exists); err != nil {
			return fmt.Errorf("checking migration %s: %w", name, err)
		}
		if exists {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("applying %s: %w", name, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			return fmt.Errorf("recording %s: %w", name, err)
		}
	}
	return nil
}

// fullyMigrated reports whether every embedded migration is already recorded — a READ-ONLY
// check (SEC-6) so a non-owner app can decide to skip Migrate (whose CREATE statements it
// cannot run) rather than fail. If schema_migrations does not exist yet, the DB is not
// migrated. It never writes, so it is safe under the restricted writer role.
func fullyMigrated(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var reg *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations')::text`).Scan(&reg); err != nil {
		return false, fmt.Errorf("checking migration state: %w", err)
	}
	if reg == nil {
		return false, nil // no schema_migrations table → not migrated
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return false, err
	}
	want := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			want++
		}
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		return false, fmt.Errorf("counting applied migrations: %w", err)
	}
	return applied >= want, nil
}
