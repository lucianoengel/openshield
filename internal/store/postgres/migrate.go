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

// validRoleName restricts an app-role name to a plain SQL identifier so it can be interpolated
// into role DDL (which cannot be parameterized) without injection risk.
func validRoleName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// EnsureAppLogin idempotently provisions a NON-OWNER LOGIN role that is a member of
// openshield_writer — the identity the application binaries connect as (PLAT-6b). It is created
// by the OWNER during migration; the app then connects as this role and, being a non-owner, cannot
// disable the append-only trigger (and, unlike SET ROLE from the owner, cannot RESET back to the
// owner). The password is escaped as a literal; the role name is a validated identifier.
func EnsureAppLogin(ctx context.Context, pool *pgxpool.Pool, role, password string) error {
	if !validRoleName(role) {
		return fmt.Errorf("invalid app role name %q", role)
	}
	if password == "" {
		return fmt.Errorf("app role password must not be empty")
	}
	lit := "'" + strings.ReplaceAll(password, "'", "''") + "'"
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
		return fmt.Errorf("checking app role: %w", err)
	}
	if !exists {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD %s IN ROLE openshield_writer`, role, lit)); err != nil {
			return fmt.Errorf("creating app role: %w", err)
		}
		return nil
	}
	// Existing role: ensure it can log in with the configured password and holds the membership,
	// and ACTIVELY re-assert that it is unprivileged (R34-13). Merely not granting SUPERUSER/CREATEROLE
	// here leaves a role that acquired them elsewhere (a prior version, a manual GRANT) still
	// privileged; NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS strips them every startup so the app
	// login can never be more than a writer.
	if _, err := pool.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS PASSWORD %s`, role, lit)); err != nil {
		return fmt.Errorf("altering app role: %w", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`GRANT openshield_writer TO %s`, role)); err != nil {
		return fmt.Errorf("granting app role membership: %w", err)
	}
	return nil
}

// MigrateIfNeeded runs Migrate only when the database is not already fully migrated. It lets a
// binary that may connect as the NON-OWNER application role start safely: on a fresh database
// (owner) it migrates; on an already-migrated one (app role, which cannot CREATE) it skips via the
// read-only fullyMigrated check. The owner-only migration path (openshield-server migrate) calls
// Migrate directly.
func MigrateIfNeeded(ctx context.Context, pool *pgxpool.Pool) error {
	done, err := fullyMigrated(ctx, pool)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	return Migrate(ctx, pool)
}
