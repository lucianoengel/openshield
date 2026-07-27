package integration

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The control plane as a REAL PROCESS.
//
// These assert things no package test can: that the binary migrates on boot, that a setting reaches the
// loop it configures, that a malformed setting stops the process instead of being silently defaulted, and
// that the subcommands an operator actually types work against a real database.

func openPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(Ctx(t), dsn)
	if err != nil {
		t.Fatalf("connecting to the stack's database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestServerMigratesAndRunsAgainstARealStack is the baseline the rest depends on: the shipped binary,
// against a database it has never seen, brings the schema up itself.
//
// It is worth having as its own test because "the server migrates on boot" is an assumption every other
// scenario makes, and a failure here would otherwise surface as a confusing failure in one of them.
func TestServerMigratesAndRunsAgainstARealStack(t *testing.T) {
	stack := StartStack(t)
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	// The binary announces nothing on a bare boot, so wait on the OBSERVABLE EFFECT rather than a log
	// line: the schema exists.
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the server to migrate a fresh database", func() bool {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
			return false
		}
		return n > 0
	})
	var applied int
	if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied < 30 {
		t.Errorf("only %d migrations applied — the binary did not bring the schema fully up", applied)
	}
	// And the tables the rest of the product depends on are actually there.
	for _, table := range []string{"audit_entries", "fleet_telemetry", "incidents", "unified_alerts",
		"config_settings", "approvals", "playbook_runs"} {
		var exists bool
		if err := pool.QueryRow(Ctx(t),
			`SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil || !exists {
			t.Errorf("table %q missing after migration (err %v)", table, err)
		}
	}
	if srv.Cmd.ProcessState != nil {
		t.Fatalf("the server exited during startup:\n%s", srv.Output())
	}
}

// TestAMalformedSettingStopsTheBinary proves PLAT-5's fail-fast reaches the ACTUAL PROCESS.
//
// The package test proves the validator rejects the value; only running the binary proves the validator is
// WIRED — that main() calls it, and calls it before doing anything else. That wiring is what no package
// test covers, and it is the difference between a typo being caught at boot and silently disabling a
// feature.
//
// IT MUST BE A BOOTSTRAP FIELD, and the reason is worth stating because it caught me: after D263 a
// DYNAMIC setting is read from the database, so an env value for one is deliberately IGNORED and can
// never fail a boot. The first version of this test used OPENSHIELD_CORRELATE_INTERVAL and asserted
// pre-D263 behaviour — the integration suite's first act was to catch a stale mental model of the config,
// which is exactly the class of drift it exists for.
func TestAMalformedSettingStopsTheBinary(t *testing.T) {
	stack := StartStack(t)
	out, err := runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_CONFIG_POLL=30 seconds", // bootstrap, and a plausible typo
	}, "config")
	if err == nil {
		t.Fatalf("the binary accepted a malformed duration — a typo in a bootstrap setting must stop the "+
			"boot rather than being silently defaulted:\n%s", out)
	}
	for _, want := range []string{"OPENSHIELD_CONFIG_POLL", "not a duration"} {
		if !contains(out, want) {
			t.Errorf("the refusal does not name %q, so an operator cannot act on it:\n%s", want, out)
		}
	}
}

// TestADynamicSettingInTheEnvironmentIsIgnoredAndReported is the other half of D263, and it is the half
// an operator is most likely to get wrong: setting a dynamic value in a unit file and expecting it to
// apply. It must not apply, and it must not be silent about that.
func TestADynamicSettingInTheEnvironmentIsIgnoredAndReported(t *testing.T) {
	stack := StartStack(t)
	out, err := runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_CORRELATE_INTERVAL=45s", // dynamic: stored in the database, not read from here
	}, "config")
	if err != nil {
		t.Fatalf("config subcommand failed: %v\n%s", err, out)
	}
	if !contains(out, "OPENSHIELD_CORRELATE_INTERVAL") {
		t.Fatalf("the field is missing from the effective output:\n%s", out)
	}
	// It reports the DEFAULT, not the environment value — the console is authoritative for dynamic
	// settings, and a host quietly disagreeing with it is the failure D263 refuses.
	if contains(out, "OPENSHIELD_CORRELATE_INTERVAL                45s") {
		t.Errorf("a dynamic setting took its value from the environment:\n%s", out)
	}
}

// TestTheConfigSubcommandReportsOriginsAndHidesSecrets — the operator surface, run for real.
func TestTheConfigSubcommandReportsOriginsAndHidesSecrets(t *testing.T) {
	stack := StartStack(t)
	const secret = "sup3r-s3cret-metrics-token"
	out, err := runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_METRICS_TOKEN=" + secret,
		"OPENSHIELD_CONFIG_POLL=45s", // bootstrap: env IS its source
	}, "config")
	if err != nil {
		t.Fatalf("config subcommand failed: %v\n%s", err, out)
	}
	if contains(out, secret) {
		t.Errorf("the config output LEAKED a secret value — an operator running this in a terminal, a "+
			"ticket or a support bundle has just published a credential:\n%s", out)
	}
	if !contains(out, "OPENSHIELD_METRICS_TOKEN") || !contains(out, "(set)") {
		t.Error("a configured secret is not reported as set, so an operator cannot tell it apart from missing")
	}
	if !contains(out, "45s") || !contains(out, "[env]") {
		t.Errorf("the effective value or its origin is missing — 'what is this process running with' must "+
			"be answerable:\n%s", out)
	}
}
