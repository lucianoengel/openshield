//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE LONGEST SEAM IN THE PRODUCT: alerts → correlation → incident → playbook → case + legal hold.
//
// Five components, two scheduled loops, a leader lease and a closed step registry, and every one of them
// has its own passing tests. That is exactly the condition under which an end-to-end chain is broken
// without anything failing: the correlation loop can be correct and never started, the playbook engine can
// be correct and never handed the incident, the trigger can be correct and never matched. The seam is
// where the value is, and it is the part nothing else in this repository exercises.
//
// It is also the scenario that first showed why: the whole chain is driven by DYNAMIC settings, and until
// D285 every one of them was read from the environment rather than from the console an operator uses. The
// test below configures the deployment the way an operator does — settings in the database, nothing in the
// process's environment — which is the only configuration whose behaviour is worth asserting.

// seedBurst writes n peer-UEBA alerts for one subject at a given risk, spread over the last few minutes.
//
// Written directly rather than produced by running peer-UEBA, deliberately: the claim under test is what
// CORRELATION AND ORCHESTRATION do with a burst, and generating a genuine statistical outlier through the
// analytics would make the test's failures ambiguous between "the detector did not fire" and "the chain
// did not run". The detector has its own tests.
func seedBurst(t *testing.T, stack *Stack, subject string, n int, risk float64) {
	t.Helper()
	pool := openPool(t, stack.DSN)
	for i := 0; i < n; i++ {
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'integration',$3, now() - make_interval(secs => $4))`,
			subject, risk, fmt.Sprintf("agent-%d", i%2), float64((n-i)*30)); err != nil {
			t.Fatalf("seeding a peer alert: %v", err)
		}
	}
}

// writeE2EPlaybook writes a playbook that exercises three DIFFERENT kinds of step: one that reads
// (enrich), one that records (tag) and one that has an effect elsewhere in the platform (open-case, which
// also places a legal hold in the same transaction).
//
// Three kinds rather than three steps, because a playbook of three tags would prove the engine loops and
// nothing about whether a step can reach the rest of the system.
func writeE2EPlaybook(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e2e-playbooks.json")
	const pb = `[{"name":"e2e-first-response",
	  "trigger":{"min_severity":"high"},
	  "steps":[{"step":"enrich"},{"step":"tag","arg":"e2e-first-response"},{"step":"open-case"}]}]`
	if err := os.WriteFile(path, []byte(pb), 0o600); err != nil {
		t.Fatalf("writing the playbook: %v", err)
	}
	return path
}

// TestAlertBurstBecomesAnIncidentAndRunsAPlaybook drives the whole chain with nothing but a seeded burst
// and a configured deployment.
//
// NOTHING IS CALLED DIRECTLY. No handler is invoked, no materializer is called, no run is started by the
// test — the only inputs are rows in peer_alerts and settings in the configuration store, which is what a
// real deployment has. Every assertion below is on a side effect the running server produced by itself.
func TestAlertBurstBecomesAnIncidentAndRunsAPlaybook(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)

	const subject = "subject-e2e-burst"
	// 0.95 is CRITICAL, comfortably over the playbook's `high` floor. Chosen well clear of the boundary
	// on purpose: a test sitting exactly on a threshold fails the day someone retunes it, and would then
	// look like a broken chain rather than a moved line.
	seedBurst(t, stack, subject, 5, 0.95)

	// The deployment, configured the way an operator configures it: in the database.
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_WINDOW", "1h")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOKS", writeE2EPlaybook(t))
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOK_INTERVAL", "1s")

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)
	pool := openPool(t, stack.DSN)

	// 1. CORRELATION materialized an incident. The burst rule ran on its own clock — no operator asked.
	var incidentID int64
	var maxRisk float64
	var alertCount int
	Eventually(t, 90*time.Second, "the burst to be correlated into an incident", func() bool {
		return scanRow(t, pool,
			`SELECT id, max_risk, alert_count FROM incidents WHERE subject_id=$1 AND kind='ueba_burst'`,
			[]any{subject}, &incidentID, &maxRisk, &alertCount)
	})
	// The incident carries the burst's own numbers. Severity is DERIVED from max_risk rather than stored,
	// so this is what decides which playbooks the incident matches.
	if maxRisk < 0.90 {
		t.Errorf("the incident's max_risk is %.2f, which is below the critical floor — the severity a "+
			"playbook trigger is compared against comes from here, so a wrong value silently changes "+
			"which playbooks run", maxRisk)
	}
	if alertCount != 5 {
		t.Errorf("the incident groups %d alerts, want the 5 that were seeded", alertCount)
	}

	// 2. THE PLAYBOOK RAN, and SUCCEEDED. A run that exists but failed would satisfy a weaker assertion
	// while meaning the opposite, so the state is asserted, not the row's existence.
	var runState string
	Eventually(t, 90*time.Second, "the playbook to run against the incident", func() bool {
		return scanRow(t, pool,
			`SELECT state FROM playbook_runs WHERE incident_id=$1 AND playbook='e2e-first-response'`,
			[]any{incidentID}, &runState) && runState != "running"
	})
	if runState != "succeeded" {
		t.Fatalf("the playbook run is %q, want succeeded\n%s", runState, srv.Output())
	}

	// 3. EVERY STEP had its effect. Asserting per step rather than on the run's state, because a run is
	// marked succeeded by the engine — which is the thing under test, and cannot be its own witness.
	var enrich, tag int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FILTER (WHERE kind='enrichment'), count(*) FILTER (WHERE kind='tag' AND body='e2e-first-response')
		   FROM incident_annotations WHERE incident_id=$1`, incidentID).Scan(&enrich, &tag); err != nil {
		t.Fatal(err)
	}
	if enrich == 0 {
		t.Error("the enrich step left no annotation, so the incident carries none of the context the " +
			"playbook exists to assemble")
	}
	if tag != 1 {
		t.Errorf("want exactly 1 tag annotation, got %d — a duplicate means the engine re-ran a completed "+
			"step, which for open-case would mean a second case and a second legal hold", tag)
	}

	// 4. THE STEP THAT REACHES OUTSIDE THE INCIDENT: open-case opened a case AND placed a legal hold, and
	// attributed both to the PLAYBOOK rather than to a person. A machine's action recorded under a
	// human's name is a corrupted audit trail.
	var caseOpener string
	if err := pool.QueryRow(Ctx(t),
		`SELECT opened_by FROM cases WHERE subject_id=$1`, subject).Scan(&caseOpener); err != nil {
		t.Fatalf("the open-case step opened no case: %v\n%s", err, srv.Output())
	}
	if caseOpener != "playbook:e2e-first-response" {
		t.Errorf("the case is attributed to %q — automated work must never be recorded under an operator's "+
			"identity", caseOpener)
	}
	var holds int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM legal_holds WHERE subject_id=$1`, subject).Scan(&holds); err != nil {
		t.Fatal(err)
	}
	if holds == 0 {
		t.Error("no legal hold was placed — opening a case without holding the subject's evidence lets " +
			"retention purge what the case exists to examine")
	}
}

// TestARecorrelatedBurstDoesNotRunThePlaybookTwice is the property that decides whether the previous test
// describes an orchestrator or a duplicate-generator.
//
// The correlation loop runs every second here, so by the time this finishes it has re-correlated the same
// burst dozens of times. Each pass upserts the subject's OPEN incident rather than inserting a new one,
// and the playbook engine claims an incident once. If either were wrong, a first-response playbook would
// open a case per tick — which is not a cosmetic defect: it is an analyst's queue filling with duplicates
// of one event, and it is how automation gets switched off.
//
// It asserts on ANNOTATIONS rather than on pages, because SIEM-12's durable dedupe would suppress a
// duplicate notification and make a genuine duplication look clean (D242).
func TestARecorrelatedBurstDoesNotRunThePlaybookTwice(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)

	const subject = "subject-e2e-once"
	seedBurst(t, stack, subject, 5, 0.95)
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOKS", writeE2EPlaybook(t))
	setDynamic(t, stack, "OPENSHIELD_PLAYBOOK_INTERVAL", "1s")

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("playbook orchestration ACTIVE", 90*time.Second)
	pool := openPool(t, stack.DSN)

	Eventually(t, 90*time.Second, "the first playbook run to finish", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM playbook_runs WHERE state='succeeded'`).Scan(&n)
		return n > 0
	})
	// Let the loops run well past the first pass. A duplication bug needs TIME to show, and asserting
	// immediately after the first success would pass against an engine that duplicates on every tick.
	time.Sleep(8 * time.Second)

	var incidents, runs, cases, tags int
	if err := pool.QueryRow(Ctx(t), `
		SELECT (SELECT count(*) FROM incidents WHERE subject_id=$1),
		       (SELECT count(*) FROM playbook_runs),
		       (SELECT count(*) FROM cases WHERE subject_id=$1),
		       (SELECT count(*) FROM incident_annotations WHERE kind='tag')`, subject).
		Scan(&incidents, &runs, &cases, &tags); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		got  int
		why  string
	}{
		{"incidents", incidents, "re-correlating a burst must EXTEND the subject's open incident, not raise a new one"},
		{"playbook runs", runs, "the engine must claim an incident once, however often it looks for work"},
		{"cases", cases, "a case per correlation tick is an analyst's queue filling with copies of one event"},
		{"tag annotations", tags, "a step must not re-run once it is done"},
	} {
		if c.got != 1 {
			t.Errorf("after ~%d correlation ticks there are %d %s, want 1 — %s\n%s",
				8, c.got, c.name, c.why, srv.Output())
		}
	}
}
