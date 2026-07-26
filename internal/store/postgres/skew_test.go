package postgres_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// PLAT-9: schema skew across a BINARY ROLLBACK.
//
// `fullyMigrated` answers `applied >= want`, which is right for "may I skip migrating?" and SILENT about
// the rollback case. Silence is the defect: running against a schema this binary does not know is bounded
// and usually benign, but running that way with NOBODY KNOWING is not.
//
// Mutation: report skew only when applied < embedded (i.e. keep the `>=` blindness) → the rollback case
// reports nothing → FAILS.
func TestSchemaSkewDetectsARolledBackBinary(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()

	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	// A freshly migrated database is LEVEL with the binary that migrated it.
	embedded, applied, err := postgres.SchemaSkew(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if embedded == 0 {
		t.Fatal("the binary embeds no migrations — the check is not looking at anything")
	}
	if applied != embedded {
		t.Fatalf("a freshly migrated database reports applied=%d embedded=%d, want level", applied, embedded)
	}

	// Simulate a BINARY ROLLBACK: the database has migrations this binary does not embed. That is
	// exactly what rolling back after a migration leaves behind.
	for _, v := range []string{"900_future", "901_future"} {
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			t.Skipf("cannot simulate a newer schema in this environment: %v", err)
		}
	}
	defer pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version LIKE '90%_future'`) //nolint:errcheck

	embedded2, applied2, err := postgres.SchemaSkew(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if applied2-embedded2 != 2 {
		t.Errorf("skew = %d (applied=%d embedded=%d), want 2 — a binary rolled back after a migration "+
			"is reading a schema whose changes it cannot know, and must not do so silently",
			applied2-embedded2, applied2, embedded2)
	}

	// AND STARTUP IS NOT PREVENTED. Refusing would turn a rollback into an outage — worse than the risk
	// it avoids, and a direct contradiction of being able to roll back at all.
	if err := postgres.MigrateIfNeeded(ctx, pool); err != nil {
		t.Errorf("a newer schema prevented startup: %v — rolling the binary back is a legitimate "+
			"incident action and must not become an outage", err)
	}
}
