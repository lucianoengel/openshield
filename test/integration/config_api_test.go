//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// THE CONFIGURATION SURFACE, driven by an operator (D292).
//
// D263 made the database authoritative for every dynamic setting and D285 wired the reading of them.
// Nothing was ever wired to WRITE one: `ApplySettings`, `Revisions`, `RollbackTo` and `Describe` had no
// caller, so the revision trail was recorded by nothing, the rollback could not be invoked, and the only
// way to change a dynamic setting in a deployed system was hand-written SQL.
//
// THIS SUITE PAPERED OVER THAT GAP. `setDynamic` writes to `config_settings` directly, because that was
// the only way — so every scenario that configured a deployment exercised the READ path against a store
// nothing in the product could fill. A helper that works around a missing surface makes the surface look
// present, which is why the gap survived four rounds of integration work.
//
// These scenarios use the API an operator actually has.

// configPost sends a change set the way a console would.
func configPost(t *testing.T, c *http.Client, base string, note string, changes map[string]string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"note": note, "changes": changes})
	if err != nil {
		t.Fatal(err)
	}
	return do(t, c, http.MethodPost, base+"/config", strings.NewReader(string(body)))
}

// TestASavedSettingTakesEffectThroughTheAPI is the promise the whole scope split rests on, made through
// the surface an operator has rather than through SQL.
func TestASavedSettingTakesEffectThroughTheAPI(t *testing.T) {
	p := newPKI(t)
	// Only the TICK is pre-seeded, and it must happen BEFORE the server boots: the loop's first wait uses
	// the interval read at loop start, so setting it through the API below cannot shorten a minute
	// already being waited. The scenario would otherwise spend that minute measuring the default rather
	// than the thing under test — whether a setting saved through the OPERATOR'S SURFACE reaches a
	// running process. The playbook path, which IS what is under test, still arrives via the API.
	_, srv, base := mtlsServer(t, p, map[string]string{"OPENSHIELD_PLAYBOOK_INTERVAL": "1s"})
	admin := p.operator(t, "admin", "root")

	code, body := configPost(t, admin, base, "enable orchestration", map[string]string{
		"OPENSHIELD_PLAYBOOKS":         writeE2EPlaybook(t),
		"OPENSHIELD_PLAYBOOK_INTERVAL": "1s",
	})
	if code != http.StatusOK {
		t.Fatalf("applying a change: %d %s", code, body)
	}
	var applied struct {
		Revision int64  `json:"revision"`
		Author   string `json:"author"`
	}
	if err := json.Unmarshal([]byte(body), &applied); err != nil {
		t.Fatal(err)
	}
	if applied.Author != "cert:root" {
		t.Errorf("the revision is attributed to %q — a configuration change is an accountable act, and "+
			"the author must be the certificate that made it", applied.Author)
	}

	// The RUNNING process picks it up: the settings watcher polls, so this needs no restart. That is the
	// difference between a configuration store and a config file with extra steps.
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)

	// And the revision trail records what changed, and from what.
	code, body = do(t, admin, http.MethodGet, base+"/config/revisions", nil)
	if code != http.StatusOK {
		t.Fatalf("reading revisions: %d %s", code, body)
	}
	if !contains(body, "OPENSHIELD_PLAYBOOK_INTERVAL") || !contains(body, "cert:root") {
		t.Errorf("the revision trail does not record the change or its author:\n%s", body)
	}
}

// TestAnInvalidChangeIsRefusedInFullAndFieldScoped covers the two properties that decide whether an
// operator can safely use this surface at all.
func TestAnInvalidChangeIsRefusedInFullAndFieldScoped(t *testing.T) {
	p := newPKI(t)
	stack, _, base := mtlsServer(t, p)
	admin := p.operator(t, "admin", "root")

	// One good key, one malformed. The WHOLE change must be refused: partial application leaves a
	// deployment in a state no operator chose, and the operator who typed it is the person who should
	// find out.
	code, body := configPost(t, admin, base, "mixed", map[string]string{
		"OPENSHIELD_CORRELATE_INTERVAL": "30s",
		"OPENSHIELD_CORRELATE_WINDOW":   "30 seconds",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a malformed value was accepted: %d %s", code, body)
	}
	if !contains(body, "OPENSHIELD_CORRELATE_WINDOW") {
		t.Errorf("the refusal does not name the offending FIELD, so a console cannot put the message next "+
			"to the input that caused it:\n%s", body)
	}
	// The good key must NOT have landed.
	pool := openPool(t, stack.DSN)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM config_settings WHERE key='OPENSHIELD_CORRELATE_INTERVAL'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("a refused change still applied one of its keys — a partially-applied configuration is a " +
			"state nobody chose")
	}

	// A BOOTSTRAP key is refused: it has to reach the process before the database does, so storing it
	// would be a value nobody reads.
	if code, body = configPost(t, admin, base, "bootstrap", map[string]string{
		"OPENSHIELD_CONFIG_POLL": "30s",
	}); code != http.StatusBadRequest {
		t.Errorf("a BOOTSTRAP setting was stored: %d %s", code, body)
	}
	// A SECRET is refused: a dump of this database must not be a dump of the deployment's credentials.
	if code, body = configPost(t, admin, base, "secret", map[string]string{
		"OPENSHIELD_METRICS_TOKEN": "hunter2",
	}); code != http.StatusBadRequest {
		t.Errorf("a SECRET was stored in the configuration database: %d %s", code, body)
	}
}

// TestTheEffectiveViewNeverReturnsASecret is the read-side half of the same promise.
func TestTheEffectiveViewNeverReturnsASecret(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	const secret = "sup3r-s3cret-metrics-token"
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_METRICS_TOKEN=" + secret,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 90*time.Second)
	admin := p.operator(t, "admin", "root")

	code, body := do(t, admin, http.MethodGet, "https://"+addr+"/config", nil)
	if code != http.StatusOK {
		t.Fatalf("reading the effective configuration: %d %s", code, body)
	}
	if contains(body, secret) {
		t.Fatalf("the effective view RETURNED A SECRET. An operator with read access to configuration "+
			"would be able to exfiltrate every credential the deployment holds, and a support bundle "+
			"containing this response would publish them:\n%s", body)
	}
	if !contains(body, "OPENSHIELD_METRICS_TOKEN") || !contains(body, `"set":true`) {
		t.Errorf("a configured secret is not reported as SET, so an operator cannot tell it apart from "+
			"missing:\n%s", body)
	}
}

// TestRollbackRestoresValuesAsANewRevision covers the operation the audit found unreachable.
func TestRollbackRestoresValuesAsANewRevision(t *testing.T) {
	p := newPKI(t)
	_, _, base := mtlsServer(t, p)
	admin := p.operator(t, "admin", "root")

	if code, body := configPost(t, admin, base, "first", map[string]string{
		"OPENSHIELD_CORRELATE_MIN_ALERTS": "3",
	}); code != http.StatusOK {
		t.Fatalf("first change: %d %s", code, body)
	}
	code, body := do(t, admin, http.MethodGet, base+"/config/revisions", nil)
	if code != http.StatusOK {
		t.Fatalf("revisions: %d %s", code, body)
	}
	var revs []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &revs); err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 {
		t.Fatalf("want 1 revision, got %d:\n%s", len(revs), body)
	}
	first := revs[0].ID

	if code, body = configPost(t, admin, base, "widen", map[string]string{
		"OPENSHIELD_CORRELATE_MIN_ALERTS": "99",
	}); code != http.StatusOK {
		t.Fatalf("second change: %d %s", code, body)
	}

	if code, body = do(t, admin, http.MethodPost,
		fmt.Sprintf("%s/config/rollback?to=%d", base, first), nil); code != http.StatusOK {
		t.Fatalf("rollback: %d %s", code, body)
	}

	// The value is back...
	code, body = do(t, admin, http.MethodGet, base+"/config", nil)
	if code != http.StatusOK {
		t.Fatalf("reading config: %d %s", code, body)
	}
	if !contains(body, `"OPENSHIELD_CORRELATE_MIN_ALERTS"`) || contains(body, `"value":"99"`) {
		t.Errorf("the rolled-back value is still 99:\n%s", body)
	}

	// ...and the history is LONGER, not shorter. Rolling back by deleting revisions would make the audit
	// trail rewritable by the same action it exists to record.
	code, body = do(t, admin, http.MethodGet, base+"/config/revisions", nil)
	if code != http.StatusOK {
		t.Fatal(body)
	}
	if err := json.Unmarshal([]byte(body), &revs); err != nil {
		t.Fatal(err)
	}
	if len(revs) != 3 {
		t.Errorf("want 3 revisions after change, change, rollback — got %d. A rollback must be recorded "+
			"as a new revision:\n%s", len(revs), body)
	}
}

// TestAResponderCannotChangeConfiguration pins the tier.
//
// Changing configuration can disable detection outright — a correlation interval of zero stops incidents
// being raised at all — so it sits at the admin tier rather than with the responder's actions.
func TestAResponderCannotChangeConfiguration(t *testing.T) {
	p := newPKI(t)
	_, _, base := mtlsServer(t, p)
	responder := p.operator(t, "responder", "rita")

	if code, body := configPost(t, responder, base, "nope", map[string]string{
		"OPENSHIELD_CORRELATE_INTERVAL": "0s",
	}); code != http.StatusForbidden {
		t.Errorf("a RESPONDER changed configuration (%d %s) — turning correlation off stops incidents "+
			"being raised at all, which is not a responder-tier act", code, body)
	}
	if code, body := do(t, responder, http.MethodGet, base+"/config", nil); code != http.StatusForbidden {
		t.Errorf("a RESPONDER read the effective configuration (%d %s) — it names every host-level "+
			"setting this deployment runs with", code, body)
	}
}
