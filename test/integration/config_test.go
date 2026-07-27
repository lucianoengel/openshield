//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// DYNAMIC CONFIGURATION, against a running process.
//
// D263 draws a hard line: a BOOTSTRAP setting comes from the environment (it has to reach the process
// before the database does), and a DYNAMIC setting comes from the DATABASE and NOWHERE ELSE. The console
// is authoritative; a host quietly disagreeing with it is the exact failure that split exists to refuse.
//
// That is a claim about the WIRING — about what main() reads — and no package test can check it. The
// config package can prove the resolver prefers the database; it cannot prove main() asks the resolver.
// Only starting the real binary, changing a setting the way an operator would, and watching what the
// process does can tell the two apart.

// writePlaybookFile writes a minimal valid playbook and returns its path. Its content does not matter to
// these tests — only whether the process LOADS it, which is observable in the process's own output.
func writePlaybookFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "playbooks.json")
	const pb = `[{"name":"integration","trigger":{"min_severity":"high"},"steps":[{"step":"tag","arg":"integration"}]}]`
	if err := os.WriteFile(path, []byte(pb), 0o600); err != nil {
		t.Fatalf("writing a playbook file: %v", err)
	}
	return path
}

// setDynamic writes a dynamic setting directly, for scenarios that must configure a deployment BEFORE
// the server process exists.
//
// SQL rather than the API is correct HERE and only here: these scenarios set a value that must be in
// place at boot, so there is no running control plane to POST to. Everywhere an operator would actually
// be involved, the scenario uses the real surface (`config_api_test.go`) — because for four rounds this
// helper was the ONLY way to write a setting, and a helper that works around a missing surface makes the
// surface look present. That is how D292's gap survived as long as it did.
func setDynamic(t *testing.T, stack *Stack, key, value string) {
	t.Helper()
	pool := openPool(t, stack.DSN)
	var rev int64
	if err := pool.QueryRow(Ctx(t),
		`INSERT INTO config_revisions (author, note) VALUES ('integration-test','') RETURNING id`).
		Scan(&rev); err != nil {
		t.Fatalf("recording a configuration revision: %v", err)
	}
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO config_settings (key, value, revision, updated_at) VALUES ($1,$2,$3, now())
		 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, revision=EXCLUDED.revision, updated_at=now()`,
		key, value, rev); err != nil {
		t.Fatalf("saving %s: %v", key, err)
	}
}

// migrateStack brings the schema up with the operator subcommand, so a test can write settings BEFORE the
// server process starts. Without this the settings table does not exist yet and the write races the boot.
func migrateStack(t *testing.T, stack *Stack) {
	t.Helper()
	if out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN}, "migrate"); err != nil {
		t.Fatalf("migrating: %v\n%s", err, out)
	}
}

// TestADynamicSettingSavedInTheDatabaseTakesEffect is the promise D263 makes to an operator: save it in
// the console, and the running deployment obeys it.
//
// Playbooks are the setting under test because the process ANNOUNCES the outcome — orchestration is
// either ACTIVE or it is not — so the assertion is on observable behaviour rather than on a value read
// back out of the same store it was written to, which would prove nothing.
func TestADynamicSettingSavedInTheDatabaseTakesEffect(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOKS", writePlaybookFile(t))

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_CONFIG_POLL=1s",
	})
	// The process says this itself, in these words, when it loads playbooks.
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)
}

// TestADynamicSettingInTheEnvironmentIsNotObeyed is the other half, and the sharper one.
//
// The server ALREADY prints "IGNORING environment values for dynamic settings [...]" when it finds one.
// So this test does not ask whether the value is documented as ignored — it asks whether the process then
// goes on to USE it anyway. A process that announces it is ignoring a setting and then obeys it is worse
// than one that silently obeys: the log actively misleads the operator reading it.
func TestADynamicSettingInTheEnvironmentIsNotObeyed(t *testing.T) {
	stack := StartStack(t)
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_PLAYBOOKS=" + writePlaybookFile(t),
	})
	// Wait for the process to have got past its configuration reporting, so "no ACTIVE line" means the
	// line was not printed rather than not printed YET.
	srv.WaitForOutput("IGNORING environment values for dynamic settings", 90*time.Second)
	srv.WaitForOutput("scheduled correlation loop ACTIVE", 90*time.Second)
	time.Sleep(2 * time.Second)

	if contains(srv.Output(), "playbook orchestration ACTIVE") {
		t.Errorf("the server announced it was IGNORING OPENSHIELD_PLAYBOOKS from the environment and then "+
			"LOADED PLAYBOOKS FROM IT — the console is supposed to be authoritative for dynamic settings, "+
			"and a log line that contradicts the process's own behaviour is worse than no line at all\n%s",
			srv.Output())
	}
}
