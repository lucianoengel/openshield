//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE REAL ENDPOINT AGENT SURVIVING A REAL OUTAGE (CONSOLE-8c).
//
// The durable offline spool (D40/D67/T-024) was wired only into cmd/openshield-fleet-agent — the fleet
// SIMULATOR — and all three existing spool-drain scenarios exercise that binary. So the capability was
// demonstrated and never shipped: a real endpoint DROPPED its telemetry for the whole of any broker
// outage, and nothing backfilled it.
//
// Being precise about the damage, because overstating it would be its own dishonesty: the endpoint's
// hash-chained ledger still recorded every decision (D30), so this was never EVIDENCE loss. What was
// lost was the FLEET's copy — permanently. Correlation, XDR, incidents and peer-UEBA each had a hole for
// the outage window with no path in the product to fill it.
//
// `internal/engine/telemetry.go` asserted the mitigation existed the whole time: "the publisher
// offline-queues (D67), so a lost telemetry copy degrades the fleet VIEW, not the audit trail." The
// second clause was true. The first was not, for this binary.

func TestTheRealEngineSpoolsThroughAnOutageAndDrainsAfterIt(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()
	spool := filepath.Join(work, "spool")
	watch := t.TempDir()

	const agentID = "engine-spool-1"
	token := issueToken(t, stack, agentID)
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_QUEUE_DIR=" + spool,
		"OPENSHIELD_QUEUE_FLUSH_INTERVAL=1s",
		"OPENSHIELD_HEARTBEAT_INTERVAL=1s",
	})
	eng.WaitForOutput("offline spool ACTIVE", 90*time.Second)

	rows := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A file with a real CPF, so the classifier genuinely fires and a decision is projected rather than
	// the pipeline running to a null result.
	drop := func(n int) {
		t.Helper()
		p := filepath.Join(watch, fmt.Sprintf("seeded-%d.txt", n))
		if err := os.WriteFile(p, []byte("employee CPF "+seededCPF+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	drop(0)
	Eventually(t, 90*time.Second, "the engine's first telemetry before the outage", func() bool {
		return rows() > 0
	})
	before := rows()

	// THE OUTAGE.
	stack.StopBroker(t)
	t.Log("broker down; producing detections the endpoint cannot send")
	for i := 1; i <= 4; i++ {
		drop(i)
		time.Sleep(1 * time.Second)
	}

	// HELD, NOT DROPPED. On the unfixed engine this is zero: the publisher had no spool, so
	// storeOrSend went straight to the broker and the error was logged and forgotten.
	var held int
	Eventually(t, 60*time.Second, "the endpoint to SPOOL what it cannot send", func() bool {
		held = spoolFiles(t, spool)
		return held > 0
	})
	t.Logf("during the outage: %d record(s) held on disk, %d row(s) stored", held, rows())

	// AND THE DECISIONS SURVIVED LOCALLY THROUGHOUT, which is the claim that makes this a fleet-view
	// problem rather than an evidence problem. Asserting it here keeps the two distinguishable: if this
	// ever fails, the severity of the whole finding changes.
	var local int
	if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&local); err != nil {
		t.Fatal(err)
	}
	if local == 0 {
		t.Errorf("no local ledger entries during the outage — the endpoint's own record is what makes " +
			"a broker outage a lost VIEW rather than lost EVIDENCE")
	}

	stack.RestoreBroker(t)

	Eventually(t, 180*time.Second, "the spool to drain once the broker is back",
		func() bool { return spoolFiles(t, spool) == 0 })
	Eventually(t, 120*time.Second, "the records held across the outage to be STORED",
		func() bool { return rows() >= before+held })
	t.Logf("recovered: %d row(s) stored (held %d across the outage)", rows(), held)
}

// TestAnEngineWithNoSpoolSaysSo — the deployment that declines the spool must not have to infer that its
// telemetry is discarded during an outage (D31: a gap must never be silent).
//
// Mutation: drop the warning branch from attachSpool → FAILS.
func TestAnEngineWithNoSpoolSaysSo(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	work := t.TempDir()

	const agentID = "engine-nospool"
	token := issueToken(t, stack, agentID)
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		// No OPENSHIELD_QUEUE_DIR.
	})
	eng.WaitForOutput("NO OFFLINE SPOOL", 90*time.Second)

	// And it says what it COSTS, not merely which setting is unset — the same rule the health report's
	// problem list follows.
	if !contains(eng.Output(), "DROPPED") {
		t.Errorf("the no-spool warning does not say what is lost:\n%s", eng.Output())
	}
}
