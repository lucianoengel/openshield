//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PLATFORM SURFACES (D307): metrics, durable ingest, the least-privilege app role, ransomware canaries
// and real-time FIM.
//
// These are the parts an operator relies on without thinking about: the endpoint a scrape watches, the
// queue that decides whether a detection survives a restart, the database role that bounds a compromised
// control plane, and the two endpoint detectors that fire on file behaviour rather than content. Each is
// configured by a setting nothing had ever set in a running process.

// TestTheMetricsEndpointRequiresItsTokenAndReportsCounters covers PLAT-4b.
func TestTheMetricsEndpointRequiresItsTokenAndReportsCounters(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	const token = "metrics-bearer-token"
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_METRICS_ADDR=" + addr,
		"OPENSHIELD_METRICS_TOKEN=" + token,
	})
	srv.WaitForOutput("subscribing to telemetry", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)
	client := &http.Client{Timeout: 10 * time.Second}

	// UNAUTHENTICATED IS REFUSED. Metrics name what the platform is doing and how much of it — an open
	// endpoint tells an attacker whether their activity has been noticed.
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the metrics endpoint served an UNAUTHENTICATED request (%d)", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ok, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("an authenticated scrape got %d\n%s", ok.StatusCode, srv.Output())
	}
	body := readAll(t, ok.Body)
	// The counters that make a silent failure visible must be present. A metrics endpoint that reports
	// only liveness tells an operator the process is up while it drops every message.
	for _, want := range []string{"openshield_"} {
		if !contains(body, want) {
			t.Errorf("the metrics output carries no %q series:\n%s", want, truncate(body, 400))
		}
	}
}

// TestTheLeastPrivilegeAppRoleCannotAlterTheSchema covers SEC-6.
//
// The control plane runs as a NON-OWNER so a compromise of it cannot drop the evidence tables. That is a
// bound on the blast radius of the platform's most exposed component, and it is worth nothing unless the
// role is actually restricted.
func TestTheLeastPrivilegeAppRoleCannotAlterTheSchema(t *testing.T) {
	stack := StartStack(t)
	if out, err := runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_APP_ROLE=openshield_app",
		"OPENSHIELD_APP_PASSWORD=app-secret",
	}, "migrate"); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}

	appDSN := replaceCredentials(stack.DSN, "openshield_app", "app-secret")
	pool := openPool(t, appDSN)

	// It can do its job.
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload) VALUES ('a','event','e','\x00'::bytea)`); err != nil {
		t.Fatalf("the app role cannot INSERT telemetry, so it cannot do its job: %v", err)
	}
	// And not the owner's.
	for _, forbidden := range []string{
		`DROP TABLE audit_entries`,
		`ALTER TABLE audit_entries DROP COLUMN payload`,
	} {
		if _, err := pool.Exec(Ctx(t), forbidden); err == nil {
			t.Errorf("the app role executed %q — the control plane runs as a NON-OWNER precisely so its "+
				"compromise cannot destroy the evidence it writes", forbidden)
		}
	}
}

// TestDurableIngestSurvivesAControlPlaneRestart covers PLAT-2.
//
// Durable ingest is the DEFAULT, and the difference it makes is invisible until something restarts: with
// core NATS a detection published while the control plane is down is gone, and a gap in evidence looks
// exactly like an endpoint with nothing to report.
func TestDurableIngestSurvivesAControlPlaneRestart(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	srv, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)

	token := issueToken(t, stack, "agent-durable")
	Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-durable",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-durable",
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	Eventually(t, 90*time.Second, "the agent to be publishing", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-durable'`).Scan(&n)
		return n > 0
	})

	// Stop the control plane while the agent keeps publishing, then start a new one.
	var before int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-durable'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	_ = srv.Cmd.Process.Kill()
	time.Sleep(4 * time.Second) // the agent publishes into the stream with nobody consuming

	Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	Eventually(t, 120*time.Second, "telemetry published during the outage to be consumed after it",
		func() bool {
			var n int
			_ = pool.QueryRow(Ctx(t),
				`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-durable'`).Scan(&n)
			return n > before
		})
}

// TestRansomwareCanariesFireOnAMassChange covers the ransomware signature.
func TestRansomwareCanariesFireOnAMassChange(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work, canaryDir := t.TempDir(), t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CANARY_DIRS=" + canaryDir,
		"OPENSHIELD_CANARY_COUNT=8",
		"OPENSHIELD_CANARY_THRESHOLD=3",
		"OPENSHIELD_CANARY_INTERVAL=500ms",
		"OPENSHIELD_CANARY_WINDOW=30s",
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	// The canaries are PLANTED by the engine; find and rewrite several, which is what encryption looks
	// like to a file monitor.
	var planted []string
	Eventually(t, 60*time.Second, "the canaries to be planted", func() bool {
		entries, err := os.ReadDir(canaryDir)
		if err != nil {
			return false
		}
		planted = planted[:0]
		for _, e := range entries {
			if !e.IsDir() {
				planted = append(planted, filepath.Join(canaryDir, e.Name()))
			}
		}
		return len(planted) >= 8
	})

	// Rewriting ONE must not fire — a detector that alerts on a single touched file would fire on
	// ordinary activity and be muted within a day.
	if err := os.WriteFile(planted[0], []byte("encrypted-1"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	// Matching the DETECTION line, not the words. The startup notice already contains "canary" and
	// "ransomware", so a loose match here reported a detection that had not happened — the same
	// match-the-prose mistake this repository's guards have hit repeatedly.
	const fired = "SUSPECTED RANSOMWARE"
	if contains(eng.Output(), fired) {
		t.Fatalf("a SINGLE changed canary raised the mass-change signal — a detector that fires on one "+
			"touched file fires on ordinary activity and is muted within a day\n%s", eng.Output())
	}

	// Rewriting several within the window is the signature.
	for i := 1; i < 6; i++ {
		if err := os.WriteFile(planted[i], []byte(fmt.Sprintf("encrypted-%d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	Eventually(t, 90*time.Second, "the mass-change canary signal to fire", func() bool {
		return contains(eng.Output(), fired)
	})
	// And it reaches the LEDGER, not only the log: a detection that exists in stderr is not evidence.
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the canary detection to be recorded in the ledger", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action >= 2`).Scan(&n)
		return n > 0
	})
}

// readAll drains a response body.
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// truncate keeps a failure message readable when the body is a metrics dump.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// replaceCredentials swaps the user and password in a DSN, so a scenario can connect AS the least-
// privilege role the migrate step provisioned.
func replaceCredentials(dsn, user, pass string) string {
	at := strings.Index(dsn, "@")
	scheme := strings.Index(dsn, "://")
	return dsn[:scheme+3] + user + ":" + pass + dsn[at:]
}

// TestARansomwareDetectionNamesTheProcessResponsible (HIPS-8).
//
// The mass-change signal above tells an operator that something is encrypting a tree. That is true and
// unactionable: without a process, the only response available is taking the whole machine off the
// network, a containment that routinely costs more than the incident.
//
// The scenario is the real one. A process holds the canaries open — as one walking a tree encrypting it
// does — the detection fires, and the engine must name THAT pid, not its own. Naming its own is the
// failure mode most available to this design, because the engine reads the canaries itself to measure
// their entropy.
func TestARansomwareDetectionNamesTheProcessResponsible(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work, canaryDir := t.TempDir(), t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CANARY_DIRS=" + canaryDir,
		"OPENSHIELD_CANARY_COUNT=8",
		"OPENSHIELD_CANARY_THRESHOLD=3",
		"OPENSHIELD_CANARY_INTERVAL=500ms",
		"OPENSHIELD_CANARY_WINDOW=30s",
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	var planted []string
	Eventually(t, 60*time.Second, "the canaries to be planted", func() bool {
		entries, err := os.ReadDir(canaryDir)
		if err != nil {
			return false
		}
		planted = planted[:0]
		for _, e := range entries {
			if !e.IsDir() {
				planted = append(planted, filepath.Join(canaryDir, e.Name()))
			}
		}
		return len(planted) >= 8
	})

	// A process holding the canaries open, exactly as one walking the tree encrypting them would be at
	// the moment the detection fires. `tail -f` needs nothing but coreutils and does not exit.
	holder := exec.Command("tail", append([]string{"-f"}, planted...)...)
	if err := holder.Start(); err != nil {
		t.Skipf("cannot start the fixture process: %v", err)
	}
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		_, _ = holder.Process.Wait()
	})

	for i := 0; i < 6; i++ {
		if err := os.WriteFile(planted[i], []byte(fmt.Sprintf("encrypted-%d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	wantPID := fmt.Sprintf("pid=%d", holder.Process.Pid)
	Eventually(t, 90*time.Second, "the detection to NAME the process holding the canaries open", func() bool {
		out := eng.Output()
		return contains(out, "RANSOMWARE SUSPECT") && contains(out, wantPID)
	})

	// AND NOT ITSELF. The engine reads the canaries to measure entropy, so it is always a candidate;
	// naming it would send an operator to kill their own agent.
	selfPID := fmt.Sprintf("pid=%d", eng.Cmd.Process.Pid)
	if contains(eng.Output(), "RANSOMWARE SUSPECT") && contains(eng.Output(), selfPID) {
		t.Fatalf("the engine named ITSELF as a ransomware suspect (%s)\n%s", selfPID, eng.Output())
	}
}
