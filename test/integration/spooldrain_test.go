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

// TestAnOutageLongerThanTheReconnectBudgetStillRecovers is the defect that the drain scenario above could
// not see, because its outage was seconds long.
//
// nats.go defaults to MaxReconnects=60 with ReconnectWait=2s — a budget of roughly TWO MINUTES, after
// which the client closes the connection permanently. No process in this product passed any reconnect
// option, so every one of them inherited that. Measured before the fix: a 4-second outage recovered fully
// (2 -> 120 rows), a 150-second one never recovered at all, and thirty seconds after the broker was back
// on the same port with its state intact the row count was still 2.
//
// For the agent that is worse than losing the outage window. It keeps producing into the disk spool that
// exists so an outage causes a gap rather than silent loss (D40/D67), and it will now never drain it —
// so the spool fills to OPENSHIELD_QUEUE_MAX and begins DROPPING THE OLDEST records. A bounded outage
// silently becomes unbounded evidence loss. For the control plane the same default meant the whole
// fleet's ingest stopping permanently while the server still ran and reported nothing wrong.
//
// TWO MINUTES IS NOT A LONG OUTAGE: a laptop closed over lunch, a switch reboot, a VPN drop, a broker
// upgrade.
//
// WHY THIS TEST IS SLOW AND CANNOT BE MADE FAST. The boundary being crossed belongs to the code being
// tested, so the outage has to outlast it for the scenario to be capable of failing. Shortening it, or
// making the budget configurable and setting it small, would exercise the configured path instead of the
// default and would pass against the very bug this exists for.
//
// THE FIRST VERSION USED 135s AND COULD NOT FAIL. Reverting MaxReconnects to 60 left it PASSING, because
// 60 attempts at ReconnectWait(2s) plus up to 1s of jitter is a budget of 120-180s, not the flat 120s the
// arithmetic suggested — so a 135s outage never exhausted it and the scenario was quietly re-proving what
// the drain scenario above already covers. The mutation is what exposed that; the window now exceeds the
// jittered worst case.
func TestAnOutageLongerThanTheReconnectBudgetStillRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("crosses the ~2 minute default reconnect budget by construction")
	}
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()
	spool := filepath.Join(work, "spool")

	const agentID = "agent-long-outage"
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
	Eventually(t, 90*time.Second, "the agent's first telemetry before the outage", func() bool {
		return rows() > 0
	})

	stack.StopBroker(t)
	// PAST THE WORST-CASE BUDGET. 60 attempts x (2s + up to 1s jitter) is at most 180s, so the outage has
	// to be longer than that — not longer than the 120s the base interval alone implies.
	t.Log("broker down; waiting past the ~180s worst-case default reconnect budget")
	time.Sleep(200 * time.Second)

	held := spoolFiles(t, spool)
	before := rows()
	if held == 0 {
		t.Fatalf("nothing was spooled across a 200s outage\n%s", agent.Output())
	}
	t.Logf("after 200s down: %d record(s) held, %d row(s) stored", held, before)

	stack.RestoreBroker(t)

	// THE ASSERTION. On the unfixed code the client has already closed permanently, so the spool never
	// empties however long this waits.
	Eventually(t, 180*time.Second, "the spool to drain after an outage longer than the reconnect budget",
		func() bool { return spoolFiles(t, spool) == 0 })

	want := before + held
	Eventually(t, 120*time.Second, "the records held across the long outage to be STORED",
		func() bool { return rows() >= want })
	t.Logf("recovered after a 200s outage: %d row(s) stored (held %d)", rows(), held)
}

// TestABrokerThatComesBackEmptyDoesNotWedgeTheFleet is PLAT-10.
//
// The distinction this rests on: a broker RESTARTED with its JetStream store recovers on its own, and a
// broker that comes back with an EMPTY store did not. `natsx.EnsureTelemetryStream` was called from exactly
// two places — controlplane.Run and the producers' UseJetStream — both at process start, so nothing
// recreated a missing stream. Measured before the fix: rows frozen for 30s+ while the agent published every
// 500ms, every publish refused with `no response from stream`, and THE CONTROL PLANE SAID NOTHING AT ALL
// while each agent's spool grew toward its ceiling and began dropping the oldest records.
//
// Ordinary ops produces it: `podman rm` and recreate the broker, or an orchestrator moving it onto fresh
// storage.
//
// The recovery here is slower than the plain drain scenario by design — the healer polls, so the assertion
// has to allow a poll interval plus a reconnect plus a drain.
func TestABrokerThatComesBackEmptyDoesNotWedgeTheFleet(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()
	spool := filepath.Join(work, "spool")

	const agentID = "agent-empty-broker"
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
	Eventually(t, 90*time.Second, "the agent's first telemetry", func() bool { return rows() > 0 })

	stack.StopBroker(t)
	Eventually(t, 60*time.Second, "records to accumulate on the spool", func() bool {
		return spoolFiles(t, spool) > 0
	})
	time.Sleep(5 * time.Second)
	held := spoolFiles(t, spool)
	before := rows()
	t.Logf("outage: %d record(s) held, %d row(s) stored", held, before)

	// THE BROKER RETURNS WITH NOTHING. Same port, so the agent and the server both reconnect — and the
	// stream they need is not there.
	stack.RestoreBrokerEmpty(t)

	// The healer has to notice the consumer is gone, recreate the stream, and resubscribe. Only then can the
	// agent's spool drain. Generous, because it is a poll interval plus a reconnect plus a drain.
	Eventually(t, 180*time.Second, "the spool to drain after the broker came back EMPTY", func() bool {
		return spoolFiles(t, spool) == 0
	})
	want := before + held
	Eventually(t, 120*time.Second, "the held records to be STORED after an empty-broker recovery",
		func() bool { return rows() >= want })
	t.Logf("recovered from an EMPTY broker: %d row(s) stored (held %d)", rows(), held)
}
