//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// BREAK-GLASS: the one documented escape from database-authoritative configuration (D317).
//
// D263 made the database the ONLY source for a dynamic setting, because an environment value that
// silently shadowed a stored one is exactly how a console and a host come to disagree with no signal.
// `OPENSHIELD_BREAKGLASS` is the deliberate exception: name a field there and its env value wins.
//
// The design's claim is a CONJUNCTION, and only the conjunction is safe: the override APPLIES **and IS
// REPORTED**. Either half alone is a bug of a different kind — an override that does not apply is a
// broken incident tool, and one that is not reported recreates the silent divergence the whole scope
// split exists to refuse. So both are asserted here, and against a RUNNING process, because whether
// main() honours the resolver is not something the config package can show.

// breakGlassSetting is the field these scenarios drive, chosen because the process ANNOUNCES the
// outcome: playbook orchestration is either ACTIVE or it is not, which is observable behaviour rather
// than a value read back out of the store it was written to.
const breakGlassSetting = "OPENSHIELD_PLAYBOOKS"

// TestABreakGlassOverrideAppliesAndIsReported is the conjunction, in one scenario.
func TestABreakGlassOverrideAppliesAndIsReported(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)

	// The DATABASE says one thing — a path that does not exist, so if the stored value won, the process
	// could not load playbooks and would say so.
	setDynamic(t, stack, breakGlassSetting, filepath.Join(t.TempDir(), "not-a-real-playbook-file.json"))
	// The loader's default tick is ONE MINUTE, which is the whole of this scenario's runtime. Shortening
	// it is not cheating: what is under test is which SOURCE wins, not how often the loop runs.
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOK_INTERVAL", "1s")
	// The ENVIRONMENT says another, and names the field as break-glass.
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_CONFIG_POLL=1s",
		breakGlassSetting + "=" + writePlaybookFile(t),
		"OPENSHIELD_BREAKGLASS=" + breakGlassSetting,
	})

	// 1. IT APPLIES. The process loaded the environment's playbook file, not the database's broken path.
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)

	// 2. IT IS REPORTED. An override nobody can see is the silent divergence D263 exists to prevent: a
	// host quietly running something the console does not show is worse than one that refuses to.
	// The exact phrase the process prints. `contains` is case-sensitive, and matching the lowercase word
	// found nothing while the uppercase line was right there — a test failure that looked like a missing
	// feature and was a missing shift key.
	if !contains(srv.Output(), "BREAK-GLASS OVERRIDES ACTIVE") {
		t.Errorf("the server honoured a break-glass override and never SAID SO. The override applying is "+
			"only half the contract — an unreported one recreates exactly the console/host divergence "+
			"the scope split refuses\n%s", srv.Output())
	}
}

// TestAnUnnamedFieldIsNotOverridden is what stops break-glass from being a general env escape.
//
// Without it, "the override applies" could be satisfied by a process that reads the environment for
// EVERY dynamic field — which is D263 undone with a reassuring name attached.
//
// IT ASSERTS WHICH VALUE WON, not that nothing happened, and getting there took two wrong turns worth
// recording:
//
//  1. The first version waited a couple of seconds and checked that orchestration had NOT started. The
//     playbook loader runs on a TICK, so that measured "the loop had not run yet" and would have passed
//     whatever the process decided — the mutation making break-glass a general escape PASSED against it.
//  2. The second version added a SECOND server as a clock. That cannot work here: the loop is
//     LEADER-ONLY, two servers against one database contend for the lock, and the control silently loses
//     — which made the test flaky rather than wrong, the worse of the two outcomes.
//
// The fix is to make the single subject its own witness. BOTH sources name a VALID but DIFFERENT
// playbook file, so the process announces orchestration either way and the announcement NAMES THE PATH.
// The tick is then proven by the line existing, and the decision is proven by which path is in it.
func TestAnUnnamedFieldIsNotOverridden(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)

	stored := writePlaybookFile(t)  // what the console says
	fromEnv := writePlaybookFile(t) // what the environment says, unnamed by break-glass
	setDynamic(t, stack, breakGlassSetting, stored)
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOK_INTERVAL", "1s")

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_CONFIG_POLL=1s",
		breakGlassSetting + "=" + fromEnv,
		// A DIFFERENT field is named, so the env value above must be ignored.
		"OPENSHIELD_BREAKGLASS=OPENSHIELD_CORRELATE_INTERVAL",
	})
	srv.WaitForOutput("IGNORING environment values for dynamic settings", 90*time.Second)
	// The loop has demonstrably run: it said so, and it said which file it read.
	srv.WaitForOutput("playbook orchestration ACTIVE", 120*time.Second)

	switch {
	case contains(srv.Output(), fromEnv):
		t.Errorf("the server loaded playbooks from the ENVIRONMENT (%s) although break-glass named a "+
			"DIFFERENT field. Break-glass is a PER-FIELD exception; if naming any field opened all of "+
			"them it would be a general env escape hatch with a reassuring name\n%s", fromEnv, srv.Output())
	case !contains(srv.Output(), stored):
		t.Errorf("the server announced orchestration from neither the stored path (%s) nor the "+
			"environment (%s), so this scenario is not observing what it claims to\n%s",
			stored, fromEnv, srv.Output())
	}
}

// TestTheConfigSurfaceShowsTheOverrideAndItsOrigin.
//
// The operator-facing half. During an incident the question is "why is this host behaving differently
// from the console", and `/config` is where it gets answered: the effective value AND where it came
// from. A surface that reported the stored value while the process ran the override would be actively
// misleading — worse than not reporting at all, because it would end the investigation at the wrong
// answer.
func TestTheConfigSurfaceShowsTheOverrideAndItsOrigin(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)

	stored := filepath.Join(t.TempDir(), "stored-playbooks.json")
	setDynamic(t, stack, breakGlassSetting, stored)
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOK_INTERVAL", "1s")
	override := writePlaybookFile(t)

	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_CONFIG_POLL=1s",
		breakGlassSetting + "=" + override,
		"OPENSHIELD_BREAKGLASS=" + breakGlassSetting,
	}, tlsEnv(m)...))
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)
	waitTCP(t, addr, 90*time.Second)

	code, body := do(t, p.operator(t, "admin", "root"), http.MethodGet, "https://"+addr+"/config", nil)
	if code != http.StatusOK {
		t.Fatalf("reading the effective configuration: %d %s", code, body)
	}
	// `effective` is an ARRAY of records, sorted by key — not a map. Worth stating because decoding it as
	// a map fails with a message about JSON shapes rather than about configuration, and sent me looking
	// in the wrong place.
	var got struct {
		Effective []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Origin string `json:"origin"`
		} `json:"effective"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decoding /config: %v\n%s", err, body)
	}
	var entry struct {
		Key    string `json:"key"`
		Value  string `json:"value"`
		Origin string `json:"origin"`
	}
	for _, e := range got.Effective {
		if e.Key == breakGlassSetting {
			entry = e
		}
	}
	if entry.Key == "" {
		t.Fatalf("/config does not report %s at all:\n%s", breakGlassSetting, body)
	}
	if !contains(entry.Origin, "break-glass") {
		t.Errorf("/config reports %s with origin %q — an operator asking why this host differs from the "+
			"console cannot tell that it is running an override", breakGlassSetting, entry.Origin)
	}
	if entry.Value == stored {
		t.Errorf("/config reports the STORED value %q while the process runs the override %q. A surface "+
			"showing what the database says rather than what the host does would end the investigation "+
			"at the wrong answer", stored, override)
	}
}
