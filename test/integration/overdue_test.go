//go:build integration

package integration

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SILENCE IS NOT COMPLIANCE (D50/D51), through the running control plane.
//
// This is the honesty claim the whole product rests on. OpenShield detects; it does not prevent an
// administrator from stopping the agent. What it CAN do is refuse to read an agent's silence as health —
// and if it cannot, then "the fleet is clean" and "the fleet stopped reporting" look identical on the
// console, which is the one failure that makes every other detection worthless.
//
// `OPENSHIELD_OVERDUE_THRESHOLD` and `_INTERVAL` are that mechanism, and neither had ever run under test
// against a real agent going quiet.

// overdueServer starts ONE control plane that both serves enrollment and runs the overdue check.
//
// One, deliberately. The overdue loop is LEADER-ONLY, so a second server against the same database
// contends for the lease and the loser silently runs nothing — which does not fail, it just makes the
// scenario depend on which process won. That is the flakiness a break-glass scenario already paid for
// once (D317), and the settings here are dynamic, so they must be stored BEFORE the process boots.
func overdueServer(t *testing.T, stack *Stack, threshold, interval string) (receiver *sink, enrollURL string) {
	t.Helper()
	migrateStack(t, stack)
	receiver = startSink(t, http.StatusOK)
	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+receiver.addr+"/hook")
	setDynamic(t, stack, "OPENSHIELD_OVERDUE_THRESHOLD", threshold)
	setDynamic(t, stack, "OPENSHIELD_OVERDUE_INTERVAL", interval)

	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	})
	srv.WaitForOutput("alert delivery enabled", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)
	return receiver, "http://" + addr + "/enroll"
}

// overdueCount is how many overdue notifications the sink has seen.
func overdueCount(s *sink) int {
	n := 0
	for _, k := range s.kinds() {
		if k == "agent-overdue" {
			n++
		}
	}
	return n
}

// TestASilentAgentIsReportedOverdueExactlyOnce.
//
// Both halves matter and the SECOND is the one that decides whether the feature is usable. An overdue
// check that re-notified on every tick would satisfy "the silence was reported" and page an on-call
// engineer once a second until someone muted the channel — after which the next real outage is silent
// too. A mechanism that cries wolf is functionally the same as one that says nothing, arrived at by a
// more annoying route.
//
// WHAT THE "ONCE" ASSERTION DOES AND DOES NOT PIN DOWN, measured rather than assumed. Three independent
// mechanisms each guarantee it, and mutating any ONE leaves the test green:
//
//  1. the rising edge — `newlyOverdue` only emits agents not already notified;
//  2. an in-memory idempotency set, window-bucketed (SIEM-12);
//  3. a DURABLE dedupe in Postgres, so a restart or failover cannot double-page (R34-13).
//
// So this scenario does NOT prove any one of them works; breaking all three is what makes it fail (it
// then sees six pages instead of one, which is what the loop would produce unsuppressed). That is a
// property defended three deep, not a vacuous test — but the distinction only became visible by
// mutating, and a comment claiming this pins down the rising edge would have been false.
//
// The layer-specific behaviour is tested where it is observable: `newlyOverdue` in
// notify_internal_test.go, the durable set in the controlplane package.
func TestASilentAgentIsReportedOverdueExactlyOnce(t *testing.T) {
	stack := StartStack(t)
	receiver, enrollURL := overdueServer(t, stack, "3s", "1s")

	const agentID = "agent-goes-quiet"
	agent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + issueToken(t, stack, agentID),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_IDENTITY_FILE=" + filepath.Join(t.TempDir(), "identity.key"),
		"OPENSHIELD_HEARTBEAT=300ms",
	})
	agent.WaitForOutput("enrolled", 90*time.Second)

	// IT MUST BE SEEN FIRST. Without this the scenario could be satisfied by a control plane that reports
	// every agent overdue always — including ones that are reporting perfectly.
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the agent's telemetry to arrive before it goes quiet", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1`, agentID).Scan(&n)
		return n > 0
	})
	if n := overdueCount(receiver); n != 0 {
		t.Fatalf("%d overdue notification(s) arrived while the agent was REPORTING — an overdue check "+
			"that fires on a live agent is noise, and noise is how the real one gets ignored", n)
	}

	// THE SILENCE.
	agent.Stop()
	Eventually(t, 90*time.Second, "the silent agent to be reported overdue", func() bool {
		return overdueCount(receiver) > 0
	})

	// AND ONLY ONCE, across several further intervals.
	time.Sleep(5 * time.Second)
	if n := overdueCount(receiver); n != 1 {
		t.Errorf("the agent was reported overdue %d times. A rising-edge alert must fire once per "+
			"outage; repeating it every interval pages someone until they mute the channel, and the "+
			"next real outage is then silent too", n)
	}
}

// TestAFlappingAgentPagesOncePerDedupeWindow.
//
// This scenario started life asserting the opposite — that an agent which recovers and fails again is
// reported AGAIN — and it failed. The premise was wrong, not the product, and the reason is worth
// keeping because it is the same trap the webhook signature scenario fell into.
//
// There are TWO dedup layers. `newlyOverdue` re-arms correctly: a recovered agent drops out of the
// notified set, so its next silence is "fresh" (covered in notify_internal_test.go, where it is
// observable). Delivery then applies a SECOND, durable check (SIEM-12) whose idempotency id is bucketed
// into a 10-minute window, so the same logical alert inside one bucket is deliberately delivered once.
//
// So the end-to-end contract is ONCE PER AGENT PER WINDOW, and that is what this asserts. The stronger
// claim — that a later window pages again — is real and NOT tested here, because observing it needs a
// ten-minute wait; it is checked at the unit layer where the bucket is an argument rather than a clock.
// Saying so is better than a scenario that sleeps for ten minutes, and much better than one that
// asserts the wrong thing and gets "fixed" until it passes.
//
// The behaviour matters to an operator: an endpoint flapping every two minutes pages once, not five
// times. That is the right default for a dead-man's switch and it is not obvious from the outside.
func TestAFlappingAgentPagesOncePerDedupeWindow(t *testing.T) {
	stack := StartStack(t)
	receiver, enrollURL := overdueServer(t, stack, "3s", "1s")

	const agentID = "agent-flaps"
	identity := filepath.Join(t.TempDir(), "identity.key")
	base := []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_IDENTITY_FILE=" + identity,
		"OPENSHIELD_HEARTBEAT=300ms",
	}

	first := Start(t, "openshield-fleet-agent",
		append(append([]string{}, base...), "OPENSHIELD_ENROLL_TOKEN="+issueToken(t, stack, agentID)))
	first.WaitForOutput("enrolled", 90*time.Second)

	// Outage one.
	first.Stop()
	Eventually(t, 90*time.Second, "the first outage to be reported", func() bool {
		return overdueCount(receiver) >= 1
	})

	// RECOVERY, outlasting several check intervals so the notified set genuinely clears — otherwise this
	// would be measuring the test's impatience rather than the dedupe window. The persisted identity
	// means no token is needed (see durability_test.go for why that matters on its own).
	pool := openPool(t, stack.DSN)
	before := verifiedRows(t, pool, agentID)
	second := Start(t, "openshield-fleet-agent", base)
	second.WaitForOutput("reusing its persisted identity", 90*time.Second)
	Eventually(t, 90*time.Second, "the recovered agent's VERIFIED telemetry to resume", func() bool {
		return verifiedRows(t, pool, agentID) > before
	})
	time.Sleep(3 * time.Second)

	// Outage two, well inside the 10-minute window.
	second.Stop()
	time.Sleep(8 * time.Second) // comfortably past the 3s threshold plus several 1s intervals

	if n := overdueCount(receiver); n != 1 {
		t.Errorf("a second outage inside the dedupe window produced %d total pages, want 1. Suppressing "+
			"the repeat is the point: an endpoint flapping every few minutes must not page an on-call "+
			"engineer once per flap, or the channel gets muted and the next real outage is silent", n)
	}
}

// verifiedRows counts an agent's VERIFIED telemetry — the same rows liveness is derived from.
func verifiedRows(t *testing.T, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1 AND verified`, agentID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
