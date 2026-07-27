//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/ed25519"
)

// PEER-UEBA, RUN FOR REAL (D303).
//
// This is the analytics that PRODUCES the alerts everything downstream consumes. The correlation,
// incident and playbook scenarios all seed `peer_alerts` BY HAND — so until now nothing proved the
// detector ever writes one, and the whole orchestration chain was verified starting from a row a test
// inserted. A detector that never fires and a detector nobody exercises look identical from the tables
// downstream.
//
// The signal is a LEAVE-ONE-OUT z-score: a subject's decayed activity against its PEERS' mean and
// stddev, so a subject never contaminates the baseline it is judged against. That shape dictates the
// scenario — several quiet peers and one busy subject — and it is why a single-agent test could not
// work: with no peers there is no baseline, and the honest answer is no risk score at all.

// TestPeerUEBARaisesAnAlertForAnOutlier drives the detector with a real fleet shape.
//
// IT USES REAL ENROLLED AGENTS, and the first version did not — it published events straight onto the
// broker and the detector never saw one. That is the product being right: `observePeer` runs only on
// VERIFIED telemetry (D44), because unverified telemetry is not evidence and must not steer a decision.
// An analytics path that scored forged events would let anyone on the broker manufacture an anomaly
// against any subject.
func TestPeerUEBARaisesAnAlertForAnOutlier(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	// A low threshold and no cooldown: the DETECTOR is under test, not the tuning. A production
	// threshold would need a fleet-scale run to trip and would make this a load test. Both are DYNAMIC
	// settings, so they are saved the way an operator saves them (D285).
	setDynamic(t, stack, "OPENSHIELD_PEER_UEBA_THRESHOLD", "0.9")
	setDynamic(t, stack, "OPENSHIELD_PEER_UEBA_COOLDOWN", "1ms")
	srv, enrollURL := startServer(t, stack)
	srv.WaitForOutput("peer-UEBA enabled", 90*time.Second)
	pool := openPool(t, stack.DSN)

	agent := func(id, subject, heartbeat string) {
		t.Helper()
		Start(t, "openshield-fleet-agent", []string{
			"OPENSHIELD_AGENT_ID=" + id,
			"OPENSHIELD_ENROLL_URL=" + enrollURL,
			"OPENSHIELD_ENROLL_TOKEN=" + issueToken(t, stack, id),
			"OPENSHIELD_NATS_URL=" + stack.NATSURL,
			"OPENSHIELD_SUBJECT=" + subject,
			"OPENSHIELD_HEARTBEAT=" + heartbeat,
		})
	}
	// Five quiet PEERS establish the baseline. Without peers the analyzer has nothing to compare
	// against and correctly declines to score anyone — that is the behaviour, not a gap.
	for i := 0; i < 5; i++ {
		agent(fmt.Sprintf("agent-quiet-%d", i), fmt.Sprintf("subject-quiet-%d", i), "3s")
	}
	// One subject two orders of magnitude outside the distribution.
	agent("agent-loud", "subject-loud", "10ms")

	Eventually(t, 120*time.Second, "peer-UEBA to raise an alert for the outlier", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM peer_alerts WHERE subject_id='subject-loud'`).Scan(&n)
		return n > 0
	})

	// AND NOT FOR THE QUIET ONES. A detector that alerts on everybody produces a queue nobody reads,
	// and would satisfy the assertion above.
	var quiet int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM peer_alerts WHERE subject_id LIKE 'subject-quiet-%'`).Scan(&quiet); err != nil {
		t.Fatal(err)
	}
	if quiet > 0 {
		t.Errorf("%d alert(s) were raised for QUIET peers — peer-UEBA's claim is relative anomaly, and a "+
			"detector that fires on the baseline itself has no signal\n%s", quiet, srv.Output())
	}

	// The alert carries the attribution and lifecycle fields the triage queue needs.
	var agentID, severity, status string
	var risk float64
	if err := pool.QueryRow(Ctx(t),
		`SELECT agent_id, risk_score, severity, status FROM peer_alerts WHERE subject_id='subject-loud' LIMIT 1`).
		Scan(&agentID, &risk, &severity, &status); err != nil {
		t.Fatal(err)
	}
	if agentID == "" {
		t.Error("the alert names no originating agent — cross-host correlation (SIEM-2) counts distinct " +
			"agents, and an unattributed alert cannot participate")
	}
	if risk < 0.9 {
		t.Errorf("the recorded risk %.2f is below the threshold that raised it", risk)
	}
	if severity == "" || status == "" {
		t.Errorf("the alert is missing lifecycle fields (severity=%q status=%q) — the actionable queue is "+
			"high/critical UNACKNOWLEDGED alerts, and a row without them cannot be triaged", severity, status)
	}
}

// TestTheRetentionPurgeDeletesAgedTelemetry covers a PRIVACY OBLIGATION (D20/D81), not a feature.
//
// Personal-adjacent telemetry accruing forever is the failure the retention window exists to prevent,
// and a purge loop that is configured but never runs looks exactly like one with nothing to delete.
func TestTheRetentionPurgeDeletesAgedTelemetry(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	pool := openPool(t, stack.DSN)

	// Two rows: one older than the window, one inside it. A purge that deleted everything would pass a
	// test that only checked the old one was gone.
	for _, r := range []struct {
		agent string
		age   string
	}{{"agent-old", "40 days"}, {"agent-new", "1 hour"}} {
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified, received_at)
			 VALUES ($1,'event',$1,'\x00'::bytea,true, now() - $2::interval)`, r.agent, r.age); err != nil {
			t.Fatalf("seeding %s: %v", r.agent, err)
		}
	}

	// Both are DYNAMIC (D285), so they are set the way an operator sets them.
	setDynamic(t, stack, "OPENSHIELD_RETENTION_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_FLEET_RETENTION", "720h") // 30 days
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("subscribing to telemetry", 90*time.Second)

	Eventually(t, 90*time.Second, "the aged row to be purged", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-old'`).Scan(&n)
		return n == 0
	})
	var recent int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-new'`).Scan(&recent); err != nil {
		t.Fatal(err)
	}
	if recent != 1 {
		t.Errorf("the purge deleted telemetry INSIDE the retention window (%d rows left) — a purge that "+
			"over-deletes destroys the evidence an investigation needs", recent)
	}

	// SIEM-10: the purge is itself a queryable compliance event. "We delete after 30 days" is a claim an
	// auditor asks for evidence of, and the deletion cannot be its own evidence.
	Eventually(t, 60*time.Second, "the purge to be recorded as a retention event", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM retention_events WHERE target='fleet_telemetry'`).Scan(&n)
		return n > 0
	})
}

// TestTheControlPlaneIngestsASignedThreatFeed covers SOAR-5's scheduled ingest.
func TestTheControlPlaneIngestsASignedThreatFeed(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	privPath, pubPath := signingKeypair(t)
	feed := filepath.Join(work, "ti.feed")
	const body = "domain evil.example\nip 203.0.113.9\n"
	if err := os.WriteFile(feed, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// The detached signature the loader expects beside the feed.
	priv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feed+".sig", ed25519Sign(priv, []byte(body)), 0o600); err != nil {
		t.Fatal(err)
	}

	// TI_FEED, its interval and its name are DYNAMIC settings, so the environment is deliberately
	// ignored for them (D285) — the first draft of this test set them there and the server said so in
	// its own log. The KEY is bootstrap: it must reach the process before the database does.
	setDynamic(t, stack, "OPENSHIELD_TI_FEED", feed)
	setDynamic(t, stack, "OPENSHIELD_TI_FEED_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_TI_FEED_NAME", "integration-feed")
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_TI_FEED_KEY=" + pubPath,
	})
	srv.WaitForOutput("subscribing to telemetry", 90*time.Second)
	pool := openPool(t, stack.DSN)

	Eventually(t, 90*time.Second, "the signed feed to be ingested into the IOC store", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM ioc_indicators WHERE value='evil.example'`).Scan(&n)
		return n > 0
	})
	// Provenance is recorded: which feed, how many indicators, whether it was signed. An IOC with no
	// provenance cannot be withdrawn when the feed that carried it is found wrong.
	var name string
	var signed bool
	var count int
	if err := pool.QueryRow(Ctx(t),
		`SELECT name, signed, indicator_count FROM ioc_feeds WHERE name='integration-feed'`).
		Scan(&name, &signed, &count); err != nil {
		t.Fatalf("the feed's provenance was not recorded: %v", err)
	}
	if !signed {
		t.Error("the feed was recorded as UNSIGNED although a verification key was configured — an " +
			"operator reading the provenance would believe an unverified feed had been checked")
	}
	if count != 2 {
		t.Errorf("recorded %d indicators, want 2", count)
	}

	// A TAMPERED feed must be refused AS A WHOLE, leaving the previous snapshot in place: stale threat
	// intel beats none, and a half-applied feed is an attacker's best outcome.
	if err := os.WriteFile(feed, []byte("domain evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second)
	var still int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM ioc_indicators WHERE feed='integration-feed'`).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != 2 {
		t.Errorf("a feed whose signature no longer verifies changed the store (%d indicators) — a bad "+
			"signature must refuse the whole feed and keep the previous snapshot\n%s", still, srv.Output())
	}
}

// ed25519Sign is a readability helper: the detached signature the feed loader expects.
func ed25519Sign(priv, body []byte) []byte { return ed25519.Sign(ed25519.PrivateKey(priv), body) }
