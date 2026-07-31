//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE INCIDENT LIFECYCLE, END TO END, IN A RUNNING DEPLOYMENT (D423/D424/D430).
//
// Each of these three has package tests that drive the functions directly. What those cannot show is the
// part that has historically been wrong in this codebase: whether the shipped binary READS the setting,
// STARTS the loop and REACHES the sink. The escalation ladder is the sharpest case — every rung of it
// could be correct and the whole feature silent, because `OPENSHIELD_ESCALATION_LADDER` is read in
// cmd/openshield-server and nothing but a running process proves it is.
//
// NOTHING HERE CALLS A FUNCTION UNDER TEST. The inputs are rows in peer_alerts, settings in the
// configuration store, and a file on disk — what a real deployment has. Every assertion is on a side
// effect the running server produced by itself, or on what arrived at a receiver outside it.

// writeLadder writes an escalation ladder whose first rung is due immediately for anything already a
// minute old, so the scenario does not have to wait out a realistic deadline.
func writeLadder(t *testing.T, sinkName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ladder.json")
	body := fmt.Sprintf(`{"rungs":[{"after_seconds":30,"sinks":[%q]}]}`, sinkName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the ladder: %v", err)
	}
	return path
}

// TestAnUnacknowledgedIncidentEscalatesInARunningDeployment (D424).
//
// The property is not "Escalate() fires a rung" — that has a package test. It is that an operator who
// writes a ladder file and points a setting at it gets escalations, from a process nobody told to start a
// loop. Every step of that is wiring, and wiring is what this suite exists for.
//
// Mutation (drop the RunEscalationLoop goroutine from cmd/openshield-server, or gate it on the value read
// at startup): nothing ever arrives at the sink → this FAILs on the wait.
func TestAnUnacknowledgedIncidentEscalatesInARunningDeployment(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	pager := startSink(t, http.StatusOK)

	const subject = "subject-e2e-escalate"
	seedBurst(t, stack, subject, 5, 0.95)

	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_WINDOW", "1h")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	// ONE named sink, so the ladder's sink name resolves and an escalation cannot arrive by accident
	// through some other path.
	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "pager=http://"+pager.addr+"/hook")
	setDynamic(t, stack, "OPENSHIELD_ESCALATION_LADDER", writeLadder(t, "pager"))
	setDynamic(t, stack, "OPENSHIELD_ESCALATION_INTERVAL", "1s")

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("incident escalation ACTIVE", 90*time.Second)
	pool := openPool(t, stack.DSN)

	var incidentID int64
	Eventually(t, 90*time.Second, "the burst to be correlated into an incident", func() bool {
		return scanRow(t, pool, `SELECT id FROM incidents WHERE subject_id=$1 AND kind='ueba_burst'`,
			[]any{subject}, &incidentID)
	})

	// The incident is a minute old by construction (seedBurst spreads alerts backwards), so the 30s rung
	// is due. Wait for an ESCALATION kind specifically — the incident's own page is also arriving at
	// this sink, and counting deliveries would be satisfied by that one.
	Eventually(t, 120*time.Second, "an escalation to reach the pager", func() bool {
		for _, k := range pager.kinds() {
			if k == "escalation" {
				return true
			}
		}
		return false
	})

	// It fired ONCE, durably: the sweep runs every second, so a rung that did not record its claim
	// would arrive dozens of times over the next few seconds.
	time.Sleep(5 * time.Second)
	escalations := 0
	for _, k := range pager.kinds() {
		if k == "escalation" {
			escalations++
		}
	}
	if escalations != 1 {
		t.Fatalf("the pager received %d escalations for one rung in five seconds of sweeps — a rung "+
			"that does not durably claim itself is how an escalation mechanism trains people to mute "+
			"it\n%s", escalations, srv.Output())
	}

	var rungs int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM incident_escalations WHERE incident_id=$1`, incidentID).Scan(&rungs); err != nil {
		t.Fatal(err)
	}
	if rungs != 1 {
		t.Errorf("incident_escalations holds %d row(s) for this incident, want 1 — the claim is what "+
			"survives a restart, and without it a leader handover re-fires every rung at once", rungs)
	}
}

// TestTroubleThatReturnsIsLinkedAndPagesDifferently (D423).
//
// The chain is: a burst correlates, an operator CLOSES it over the real API with a real certificate, the
// same trouble returns, and the second incident both links to the first and says so on the pager.
//
// Closing it over mTLS rather than with an UPDATE is the point. The recurrence link keys on the incident
// having LEFT the open state, and the only thing that legitimately moves it is a transition an
// authenticated operator made — which is also what proves the forward-only lifecycle still refuses to
// bring the closed one back.
func TestTroubleThatReturnsIsLinkedAndPagesDifferently(t *testing.T) {
	p := newPKI(t)
	pager := startSink(t, http.StatusOK)
	stack, srv, base := mtlsServer(t, p, map[string]string{
		"OPENSHIELD_CORRELATE_INTERVAL":   "1s",
		"OPENSHIELD_CORRELATE_WINDOW":     "1h",
		"OPENSHIELD_CORRELATE_MIN_ALERTS": "3",
		"OPENSHIELD_ALERT_WEBHOOK":        "http://" + pager.addr + "/hook",
	})
	_ = srv
	pool := openPool(t, stack.DSN)
	responder := p.operator(t, "responder", "alice")

	const subject = "subject-e2e-recur"
	seedBurst(t, stack, subject, 4, 0.95)

	var first int64
	Eventually(t, 90*time.Second, "the first incident", func() bool {
		return scanRow(t, pool, `SELECT id FROM incidents WHERE subject_id=$1 AND state='open'`,
			[]any{subject}, &first)
	})
	Eventually(t, 60*time.Second, "the first incident to page", func() bool { return pager.count() >= 1 })

	// A responder closes it, over mutual TLS, through the shipped route.
	code, body := do(t, responder, http.MethodPost,
		fmt.Sprintf("%s/incidents/transition?id=%d&to=closed", base, first), nil)
	if code != http.StatusOK {
		t.Fatalf("closing the incident = %d: %s", code, body)
	}

	// The same trouble returns. A fresh burst, because the correlation window is still open.
	seedBurst(t, stack, subject, 4, 0.96)

	var second, recurrenceOf int64
	var recurrenceCount int
	Eventually(t, 90*time.Second, "a SECOND incident linked to the first", func() bool {
		return scanRow(t, pool,
			`SELECT id, coalesce(recurrence_of,0), recurrence_count FROM incidents
			  WHERE subject_id=$1 AND state='open' AND id <> $2`,
			[]any{subject, first}, &second, &recurrenceOf, &recurrenceCount)
	})
	if recurrenceOf != first {
		t.Fatalf("incident %d links to %d, want %d — without it an operator cannot tell new trouble "+
			"from the second time somebody closed the same thing, and those warrant opposite responses",
			second, recurrenceOf, first)
	}
	if recurrenceCount != 1 {
		t.Errorf("recurrence_count = %d, want 1", recurrenceCount)
	}

	// AND THE PAGE SAYS SO. The link is only worth having where the decision is made.
	Eventually(t, 60*time.Second, "a page announcing the recurrence", func() bool {
		return strings.Contains(strings.Join(pager.details(), "\n"), "RECURRENCE #1")
	})

	// The forward-only lifecycle is unchanged: the closed incident cannot be reopened.
	code, _ = do(t, responder, http.MethodPost,
		fmt.Sprintf("%s/incidents/transition?id=%d&to=open", base, first), nil)
	if code != http.StatusConflict {
		t.Fatalf("reopening a closed incident = %d, want 409 — recurrence is metadata ABOUT a sequence "+
			"of incidents, not a way to resurrect one, and MTTA/MTTR depend on that staying true", code)
	}
}

// TestBackfillCorrelatesAWindowNobodyWasWatching (D430).
//
// The scenario is the outage it exists for: alerts arrive while correlation is NOT RUNNING, the live loop
// later has no window that reaches them, and an operator replays the range. What must be true afterwards
// is that the incident exists, that nobody was paged for it, and that the fleet's measured response is
// untouched by it.
func TestBackfillCorrelatesAWindowNobodyWasWatching(t *testing.T) {
	p := newPKI(t)
	pager := startSink(t, http.StatusOK)
	stack, srv, base := mtlsServer(t, p, map[string]string{
		// Correlation is OFF. This is the outage: the loop runs and does nothing, exactly as a
		// deployment with the interval left at zero does.
		"OPENSHIELD_CORRELATE_INTERVAL": "0s",
		"OPENSHIELD_ALERT_WEBHOOK":      "http://" + pager.addr + "/hook",
	})
	_ = srv
	pool := openPool(t, stack.DSN)
	admin := p.operator(t, "admin", "root")

	// A burst three days ago — outside any live window even once correlation is turned back on.
	const subject = "subject-e2e-backfill"
	for i := 0; i < 4; i++ {
		if _, err := pool.Exec(Ctx(t),
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1, 0.95, 'integration', 'agent-a', now() - interval '72 hours' + make_interval(mins => $2))`,
			subject, i); err != nil {
			t.Fatalf("seeding the old burst: %v", err)
		}
	}
	// Correlation comes back. It sees nothing: the alerts are three days outside its window.
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_WINDOW", "1h")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	time.Sleep(5 * time.Second)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM incidents WHERE subject_id=$1`, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("the LIVE loop correlated %d incident(s) for a three-day-old burst; it must see "+
			"nothing, or this scenario proves nothing about backfill", n)
	}
	pagesBefore := pager.count()

	// The operator replays the range.
	since := time.Now().UTC().Add(-96 * time.Hour).Format(time.RFC3339)
	code, body := do(t, admin, http.MethodPost, base+"/correlate/backfill?since="+since, nil)
	if code != http.StatusOK {
		t.Fatalf("backfill = %d: %s", code, body)
	}
	var res struct {
		Steps int `json:"steps"`
		Burst int `json:"burst_incidents"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decoding the backfill result: %v (%s)", err, body)
	}
	if res.Burst < 1 {
		t.Fatalf("the backfill raised %d incidents across %d steps — alerts that fell outside the "+
			"window because correlation was NOT RUNNING are exactly the ones nothing else will ever "+
			"join", res.Burst, res.Steps)
	}

	var backfilled bool
	if !scanRow(t, pool, `SELECT backfilled FROM incidents WHERE subject_id=$1`, []any{subject}, &backfilled) {
		t.Fatal("the backfill reported incidents and none exist for the subject")
	}
	if !backfilled {
		t.Error("the incident is not marked backfilled — an operator reading it has no way to know its " +
			"timestamps do not mean what they usually do")
	}

	// NOBODY WAS PAGED. Replaying four days of history must not ring the alarm for something long over,
	// or the pager gets muted and the next LIVE incident is muted with it.
	time.Sleep(3 * time.Second)
	if got := pager.count(); got != pagesBefore {
		t.Fatalf("the backfill delivered %d page(s)", got-pagesBefore)
	}

	// AND THE RESPONSE METRICS DO NOT SEE IT. Its created_at is when the backfill ran, so its detection
	// latency is the age of the alert; averaged in, one backfill moves the fleet's measured response
	// arbitrarily.
	analyst := p.operator(t, "analyst", "carol")
	code, body = do(t, analyst, http.MethodGet, base+"/report/response", nil)
	if code != http.StatusOK {
		t.Fatalf("response report = %d: %s", code, body)
	}
	var report struct {
		Incidents        int `json:"incidents"`
		DetectionLatency struct {
			Count    int `json:"count"`
			Excluded int `json:"excluded"`
		} `json:"detection_latency"`
	}
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("decoding the response report: %v (%s)", err, body)
	}
	if report.Incidents != 0 || report.DetectionLatency.Count != 0 || report.DetectionLatency.Excluded != 0 {
		t.Fatalf("the response report counts the backfilled incident (incidents=%d count=%d excluded=%d) "+
			"— and not as excluded either: 'excluded' means an incident that COULD have contributed to "+
			"the response process, which a retrospective one was never part of",
			report.Incidents, report.DetectionLatency.Count, report.DetectionLatency.Excluded)
	}

	// A LIVE incident raised now IS measured, so the exclusion above is not "the report is empty".
	seedBurst(t, stack, "subject-e2e-backfill-live", 4, 0.95)
	Eventually(t, 90*time.Second, "the live incident to reach the response report", func() bool {
		_, b := do(t, analyst, http.MethodGet, base+"/report/response", nil)
		var r struct {
			Incidents int `json:"incidents"`
		}
		_ = json.Unmarshal([]byte(b), &r)
		return r.Incidents > 0
	})
}
