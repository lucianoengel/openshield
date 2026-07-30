//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE HALF OF THE OFFLINE QUEUE THAT WAS NEVER TESTED: recovery.
//
// D40/D67's claim is "spool signed telemetry when the control plane is unreachable and RE-SEND IT ON
// RECONNECT, so an outage causes a gap, not silent loss". TestTelemetryIsSpooledDuringAnOutage covers the
// first clause — it stops the broker and asserts the spool directory becomes non-empty. Nothing ever
// brought the broker BACK. So `Queue.Drain`, `SignedPublisher.Flush`, and the NATS RECONNECT that both
// depend on ran in no integration test, and the claim was half-asserted: the gap was proven, the filling
// in was not.
//
// WHY AN EMPTY SPOOL IS THE RIGHT ASSERTION, and a row count alone is not. The agent keeps producing after
// the broker returns, so "rows increased" is satisfied by an agent that dropped every spooled record and
// resumed. `Queue.Drain` removes a record ONLY after its send succeeds and stops at the first failure,
// keeping that record and the rest — so a spool that has become EMPTY is proof that every record in it was
// delivered, and it is proof that does not encode the on-disk format.

// spoolFiles counts records currently on the spool.
func spoolFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return len(entries)
}

// TestASpooledOutageDrainsWhenTheBrokerReturns is the recovery half of D40/D67.
func TestASpooledOutageDrainsWhenTheBrokerReturns(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()
	spool := filepath.Join(work, "spool")

	const agentID = "agent-draining"
	token := issueToken(t, stack, agentID)
	agent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_QUEUE_DIR=" + spool,
		"OPENSHIELD_SEQ_FILE=" + filepath.Join(work, "seq"),
		"OPENSHIELD_HEARTBEAT=500ms",
	})
	agent.WaitForOutput("enrolled", 90*time.Second)

	rows := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "the agent's first telemetry before any outage", func() bool {
		return rows() > 0
	})

	// THE OUTAGE. The BROKER goes away — the only outage an endpoint actually experiences; a control plane
	// that stops changes nothing the agent can see.
	stack.StopBroker(t)

	Eventually(t, 60*time.Second, "records to accumulate on the spool", func() bool {
		return spoolFiles(t, spool) > 0
	})
	// Let more accumulate, so the drain has real work and the assertion is not about one record. A spool
	// holding a single item would be drained by a Flush that stopped after the first record, which is the
	// exact failure mode `Drain`'s stop-at-first-error contract makes possible.
	time.Sleep(8 * time.Second)
	held := spoolFiles(t, spool)
	before := rows()
	if held == 0 {
		t.Fatalf("nothing was spooled during the outage\n%s", agent.Output())
	}
	t.Logf("outage: %d record(s) held on the spool, %d row(s) stored before it", held, before)

	// THE RECOVERY, which is what this scenario exists for.
	stack.RestoreBroker(t)

	Eventually(t, 120*time.Second, "the spool to DRAIN — every held record delivered", func() bool {
		return spoolFiles(t, spool) == 0
	})

	// And the delivered records actually landed. An empty spool with no new rows would mean Drain removed
	// records it had not delivered, which is the silent loss the queue exists to prevent (D31).
	//
	// EVENTUALLY, NOT IMMEDIATELY, and reading it once is a race I wrote and then had to diagnose. An
	// empty spool means the records reached the BROKER; the row appears only once the control plane has
	// CONSUMED them off JetStream and written them. Those are two different milestones and the second
	// lags the first, so the single read reported "the spool emptied but 0 rows appeared" — which reads
	// exactly like the catastrophic version of this bug (Drain discarding undelivered records) and is
	// not it. Worth the comment: the difference between "delivered" and "stored" is invisible in the
	// count and the wrong reading is the alarming one.
	want := before + held
	Eventually(t, 120*time.Second, "every drained record to be STORED, not merely accepted by the broker",
		func() bool { return rows() >= want })
	t.Logf("recovered: %d row(s) stored (held %d, %d before the outage)", rows(), held, before)
}
