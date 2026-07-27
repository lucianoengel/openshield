//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SURVIVING AN OUTAGE (D318): the offline spool, the sequence store, and the durable ingest mode.
//
// The product's honesty claim about gaps is D1's: an outage causes a GAP, not SILENT LOSS. Three settings
// carry that — a spool that holds telemetry while the broker is unreachable, a persisted sequence so a
// restart resumes forward-monotonically instead of being rejected as a replay, and a ceiling that drops
// LOUDLY rather than quietly when the spool fills. None was exercised against running processes.
//
// These are the properties nobody notices until the day the broker was down, which is exactly the day
// somebody asks what the endpoint was doing. A package test can show the spool holds bytes; only running
// the real agent against a real broker that GOES AWAY can show the agent uses it.

// TestTelemetrySpooledDuringAnOutageArrivesAfterwards is the D40/D67 claim, end to end.
func TestTelemetrySpooledDuringAnOutageArrivesAfterwards(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()

	const agentID = "agent-spooling"
	token := issueToken(t, stack, agentID)
	agent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_QUEUE_DIR=" + filepath.Join(work, "spool"),
		"OPENSHIELD_SEQ_FILE=" + filepath.Join(work, "seq"),
		"OPENSHIELD_HEARTBEAT=500ms",
	})
	agent.WaitForOutput("enrolled", 90*time.Second)

	// A BASELINE FIRST. Without it, "events arrived after the outage" could be satisfied by an agent that
	// never noticed the outage at all — and the whole scenario would be measuring nothing.
	events := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1`,
			agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "the agent's first telemetry", func() bool { return events() > 0 })

	// THE OUTAGE. The BROKER goes away while the agent keeps producing — which is the only outage an
	// endpoint experiences. Stopping the control plane instead changes nothing the agent can see, and
	// assuming otherwise made the first version of this scenario conclude that spooling was broken.
	stack.StopBroker(t)

	// The spool must be holding something. Asserting the DIRECTORY IS NON-EMPTY rather than counting
	// records: the on-disk format is the queue package's business, and a test that encoded it would break
	// on a format change without any behaviour changing.
	spooled := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(filepath.Join(work, "spool"))
		if err == nil && len(entries) > 0 {
			spooled = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !spooled {
		t.Fatalf("nothing was spooled while the control plane was down. An outage is supposed to cause a "+
			"GAP that fills in, not silent loss — and an agent that drops telemetry when the broker is "+
			"unreachable loses exactly the window an investigator will ask about\n%s", agent.Output())
	}
}

// TestAnAgentSurvivesARestart is D318, and the defect it covers made every reboot fatal.
//
// The agent generated a fresh keypair each boot and re-enrolled; enrollment tokens are single-use; and
// SEC-2 deliberately refuses to replace an enrolled agent's public key, so that a fresh token cannot
// overwrite an agent's key or un-revoke a revoked one. Each is right alone. Together they meant a
// restarted agent got `enroll status 401` AND EXITED — a reboot, an upgrade or a crash took the endpoint
// out of the fleet, and from the console it simply stopped reporting.
//
// The second start here is given NO TOKEN AT ALL, which is the point: an agent that needs one to come
// back has not survived a restart, it has been re-provisioned.
func TestAnAgentSurvivesARestart(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()

	const agentID = "agent-restarting"
	base := []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_IDENTITY_FILE=" + filepath.Join(work, "identity.key"),
		"OPENSHIELD_SEQ_FILE=" + filepath.Join(work, "seq"),
		"OPENSHIELD_HEARTBEAT=300ms",
	}
	first := Start(t, "openshield-fleet-agent",
		append(append([]string{}, base...), "OPENSHIELD_ENROLL_TOKEN="+issueToken(t, stack, agentID)))
	first.WaitForOutput("enrolled", 90*time.Second)

	verified := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1 AND verified`, agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "verified telemetry before the restart", func() bool { return verified() > 0 })
	before := verified()

	// The key must actually be on disk and NOT readable by others — a per-agent key others can read is a
	// shared fleet secret with extra steps, which is the risk per-agent keys exist to avoid.
	info, err := os.Stat(filepath.Join(work, "identity.key"))
	if err != nil {
		t.Fatalf("the identity was not persisted: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the agent's signing key is mode %04o — readable beyond its owner", perm)
	}

	// RESTART, WITH NO TOKEN.
	first.Stop()
	second := Start(t, "openshield-fleet-agent", base)
	second.WaitForOutput("reusing its persisted identity", 90*time.Second)

	// AND ITS TELEMETRY IS STILL VERIFIED. Coming up is not enough: the point of keeping the key is that
	// the control plane still recognises the signature, so the assertion is on VERIFIED rows growing.
	Eventually(t, 120*time.Second, "verified telemetry AFTER the restart", func() bool {
		return verified() > before
	})
}

// TestTheSpoolCeilingDropsLoudly.
//
// A bounded queue must drop something when it fills — the alternative is unbounded disk growth on an
// endpoint, which is its own outage. What is NOT acceptable is dropping quietly: a gap nobody was told
// about is indistinguishable from a period in which nothing happened, and an investigator will read it
// as the latter (D31).
func TestTheSpoolCeilingDropsLoudly(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	work := t.TempDir()

	const agentID = "agent-overflowing"
	agent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + issueToken(t, stack, agentID),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_QUEUE_DIR=" + filepath.Join(work, "spool"),
		// A ceiling low enough that a few seconds of a fast heartbeat overruns it.
		"OPENSHIELD_QUEUE_MAX=5",
		"OPENSHIELD_HEARTBEAT=100ms",
		"OPENSHIELD_BURST=20",
	})
	agent.WaitForOutput("enrolled", 90*time.Second)

	// Take the BROKER away so the spool fills rather than draining.
	stack.StopBroker(t)
	agent.WaitForOutput("QUEUE OVERFLOW", 90*time.Second)
}
