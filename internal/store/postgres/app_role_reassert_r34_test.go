package postgres_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// TestEnsureAppLoginStripsPrivileges (R34-13): the existing-role branch of EnsureAppLogin must
// ACTIVELY re-assert that the app login is unprivileged. A role that acquired SUPERUSER / CREATEROLE
// elsewhere (a prior version, a manual GRANT) must be stripped on the next startup — merely not
// granting them is not enough.
//
// The test escalates the role directly (as owner), re-runs EnsureAppLogin, and asserts the privileges
// are gone. Mutation: dropping NOSUPERUSER/NOCREATEROLE from the ALTER leaves the role privileged and
// these assertions FAIL.
func TestEnsureAppLoginStripsPrivileges(t *testing.T) {
	owner := requireDB(t)
	ctx := context.Background()
	if err := postgres.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	const role = "openshield_app"
	if err := postgres.EnsureAppLogin(ctx, owner, role, "testpass"); err != nil {
		t.Fatalf("provision app role: %v", err)
	}

	// Escalate the role behind EnsureAppLogin's back (as owner) — the drift R34-13 guards against.
	if _, err := owner.Exec(ctx, `ALTER ROLE openshield_app SUPERUSER CREATEROLE CREATEDB`); err != nil {
		t.Fatalf("escalating role for the test: %v", err)
	}
	assertPriv := func(when string, wantSuper, wantCreateRole, wantCreateDB bool) {
		var super, createRole, createDB bool
		if err := owner.QueryRow(ctx,
			`SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=$1`, role).
			Scan(&super, &createRole, &createDB); err != nil {
			t.Fatalf("reading role attrs (%s): %v", when, err)
		}
		if super != wantSuper || createRole != wantCreateRole || createDB != wantCreateDB {
			t.Fatalf("%s: super=%v createrole=%v createdb=%v; want %v/%v/%v",
				when, super, createRole, createDB, wantSuper, wantCreateRole, wantCreateDB)
		}
	}
	assertPriv("after escalation", true, true, true) // sanity: the escalation took

	// Re-run EnsureAppLogin — it must strip the privileges back off.
	if err := postgres.EnsureAppLogin(ctx, owner, role, "testpass"); err != nil {
		t.Fatalf("re-running EnsureAppLogin: %v", err)
	}
	assertPriv("after re-assert", false, false, false)

	// Cleanup so a re-run of the suite starts clean (the role persists across the DROP-tables reset).
	_, _ = owner.Exec(ctx, `DROP ROLE IF EXISTS openshield_app`)
}
