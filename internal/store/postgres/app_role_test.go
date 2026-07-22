package postgres_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// withUser swaps the userinfo in a DSN so the test can connect as the provisioned app role.
func withUser(dsn, user, pass string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}

// PLAT-6b / SEC-6: the application must run as a NON-OWNER role that can do the app's writes but
// cannot disable the append-only trigger — the property that makes the DB-level ledger boundary
// real in the running product. The negative is proven against a REAL adversary path: the app role
// attempts the exact DDL an attacker with the app credential would, including after RESET ROLE, and
// the test contrasts with the OWNER (who CAN disable it) so the app's failure is a genuine
// authorization boundary, not a no-op operation.
func TestAppRoleCannotBypassLedgerBoundary(t *testing.T) {
	owner := requireDB(t)
	ctx := context.Background()
	if err := postgres.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := postgres.EnsureAppLogin(ctx, owner, "openshield_app", "testpass"); err != nil {
		t.Fatalf("provision app role: %v", err)
	}
	appDSN := withUser(dsn(), "openshield_app", "testpass")
	app, err := pgxpool.New(ctx, appDSN)
	if err != nil {
		t.Fatalf("connect as app role: %v", err)
	}
	defer app.Close()

	// Positive: the app role can write an aggregate table AND append to the ledger (via the real
	// ledger, which runs fullyMigrated → skip → append as a non-owner).
	if _, err := app.Exec(ctx, `INSERT INTO peer_alerts (subject_id, risk_score, context_version) VALUES ('b-t', 0.5, 'v1')`); err != nil {
		t.Fatalf("app role cannot write an aggregate table it needs: %v", err)
	}
	signer, _ := core.NewSigner()
	led, err := postgres.Open(ctx, appDSN, signer)
	if err != nil {
		t.Fatalf("app role cannot open the ledger: %v", err)
	}
	defer led.Close()
	if err := led.Append(ctx, entry("b-a")); err != nil {
		t.Fatalf("app role cannot append to the ledger: %v", err)
	}

	// Negative (the boundary): the app role cannot disable the append-only trigger…
	if _, err := app.Exec(ctx, `ALTER TABLE audit_entries DISABLE TRIGGER openshield_audit_append_only_trg`); err == nil {
		t.Fatal("app role DISABLED the append-only trigger — SEC-6 boundary is open")
	}
	// …not even after RESET ROLE (it is a real non-owner LOGIN role, not a SET ROLE from the owner
	// that RESET could unwind).
	_, _ = app.Exec(ctx, `RESET ROLE`)
	if _, err := app.Exec(ctx, `ALTER TABLE audit_entries DISABLE TRIGGER openshield_audit_append_only_trg`); err == nil {
		t.Fatal("app role disabled the trigger after RESET ROLE — a leaked app credential could escalate")
	}
	// …and cannot DELETE a ledger row.
	if _, err := app.Exec(ctx, `DELETE FROM audit_entries`); err == nil {
		t.Fatal("app role DELETED from the append-only ledger")
	}

	// Contrast: the OWNER genuinely CAN disable the trigger — so the app's failures above are a real
	// authorization boundary, not an operation that is impossible for everyone (a false pass). Re-
	// enable immediately so the ledger stays protected for the rest of the run.
	if _, err := owner.Exec(ctx, `ALTER TABLE audit_entries DISABLE TRIGGER openshield_audit_append_only_trg`); err != nil {
		t.Fatalf("owner cannot disable the trigger — the negative test may be a false pass: %v", err)
	}
	if _, err := owner.Exec(ctx, `ALTER TABLE audit_entries ENABLE TRIGGER openshield_audit_append_only_trg`); err != nil {
		t.Fatalf("re-enable trigger: %v", err)
	}
}
