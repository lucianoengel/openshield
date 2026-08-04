package controlplane_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SOAR-6: response metrics derived from the timestamps SOAR-2 was careful to record.
//
// The forward-only lifecycle (D250) exists so these are measurable at all — "a lifecycle that can move
// backwards makes MTTA/MTTR unmeasurable" is the reason it was constrained. These tests are that
// constraint being cashed in.

// seedTimedIncident writes an incident with explicit timestamps so a duration is exact rather than
// dependent on how long the test took to run.
func seedTimedIncident(t *testing.T, pool *pgxpool.Pool, subject string,
	firstSeen, createdAt time.Time, ackAt *time.Time, state string, transitionedAt *time.Time) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count,
		                        first_seen, last_seen, created_at, acknowledged_at, acknowledged_by,
		                        transitioned_at, transitioned_by)
		 VALUES ('cross_domain',$1,$2,3,0.9,1,$3,$3,$4,$5,CASE WHEN $5::timestamptz IS NULL THEN '' ELSE 'operator:a' END,$6,
		         CASE WHEN $6::timestamptz IS NULL THEN NULL ELSE 'operator:b' END)
		 RETURNING id`,
		subject, state, firstSeen, createdAt, ackAt, transitionedAt).Scan(&id); err != nil {
		t.Fatalf("seeding incident %s: %v", subject, err)
	}
	return id
}

// TestTransitionOffOpenRecordsTheAcknowledgement covers the defect SOAR-6 surfaced: an operator who moved
// an incident straight to `triaged` never had their acknowledgement recorded, so that incident was
// permanently unmeasurable for time-to-acknowledge — the exact outcome the forward-only lifecycle exists
// to prevent.
//
// Mutation A: drop the COALESCE stamp → the directly-triaged incident has no acknowledgement → FAILS.
// Mutation B: stamp unconditionally (no COALESCE) → a later operator overwrites the first → FAILS.
func TestTransitionOffOpenRecordsTheAcknowledgement(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// (1) Straight from open to triaged: the transitioning operator IS the acknowledger.
	direct := seedTimedIncident(t, pool, "subject-soar6-direct", now.Add(-time.Hour), now.Add(-time.Hour), nil,
		controlplane.IncidentOpen, nil)
	if err := srv.TransitionIncident(ctx, direct, controlplane.IncidentTriaged, "cert:carol"); err != nil {
		t.Fatalf("transition: %v", err)
	}
	var ackBy string
	var ackAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT acknowledged_by, acknowledged_at FROM incidents WHERE id=$1`,
		direct).Scan(&ackBy, &ackAt); err != nil {
		t.Fatal(err)
	}
	if ackAt == nil || ackBy != "cert:carol" {
		t.Errorf("open→triaged recorded acknowledged_by=%q at=%v — an operator who triages directly erases "+
			"their own response time, and that incident can never be measured", ackBy, ackAt)
	}

	// (2) An EXISTING acknowledgement is never overwritten: first-ack-wins (SIEM-11b) survives.
	acked := seedTimedIncident(t, pool, "subject-soar6-acked", now.Add(-time.Hour), now.Add(-time.Hour), nil,
		controlplane.IncidentOpen, nil)
	if _, err := srv.AcknowledgeIncident(ctx, acked, "cert:first"); err != nil {
		t.Fatal(err)
	}
	var firstAckAt time.Time
	if err := pool.QueryRow(ctx, `SELECT acknowledged_at FROM incidents WHERE id=$1`, acked).Scan(&firstAckAt); err != nil {
		t.Fatal(err)
	}
	if err := srv.TransitionIncident(ctx, acked, controlplane.IncidentContained, "cert:second"); err != nil {
		t.Fatal(err)
	}
	var laterBy string
	var laterAt time.Time
	if err := pool.QueryRow(ctx, `SELECT acknowledged_by, acknowledged_at FROM incidents WHERE id=$1`,
		acked).Scan(&laterBy, &laterAt); err != nil {
		t.Fatal(err)
	}
	if laterBy != "cert:first" || !laterAt.Equal(firstAckAt) {
		t.Errorf("a later transition overwrote the acknowledgement (by=%q at=%v, want operator:first at %v) — "+
			"first-ack-wins attribution is lost and MTTA silently improves every time someone touches it",
			laterBy, laterAt, firstAckAt)
	}

	// (3) A REFUSED (backward) transition records nothing.
	closed := seedTimedIncident(t, pool, "subject-soar6-closed", now.Add(-time.Hour), now.Add(-time.Hour), nil,
		controlplane.IncidentClosed, &now)
	if err := srv.TransitionIncident(ctx, closed, controlplane.IncidentTriaged, "cert:late"); err == nil {
		t.Fatal("a backward transition was accepted")
	}
	var closedAck *time.Time
	if err := pool.QueryRow(ctx, `SELECT acknowledged_at FROM incidents WHERE id=$1`, closed).Scan(&closedAck); err != nil {
		t.Fatal(err)
	}
	if closedAck != nil {
		t.Error("a REFUSED transition stamped an acknowledgement — the stamp is not atomic with the move")
	}
}

// TestResponseMetricsSeparatesPlatformLagFromAnalystTime is the core measurement.
//
// Merging the three would produce one number that answers no question: detection latency is OUR lag and
// an analyst cannot influence it, so charging them for the correlation window would make MTTA a function
// of OPENSHIELD_CORRELATE_INTERVAL.
func TestResponseMetricsSeparatesPlatformLagFromAnalystTime(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	// Raised 10 min after its first alert, acked 5 min later, closed 30 min after that.
	first := now.Add(-2 * time.Hour)
	created := first.Add(10 * time.Minute)
	ack := created.Add(5 * time.Minute)
	closed := created.Add(35 * time.Minute)
	seedTimedIncident(t, pool, "subject-soar6-full", first, created, &ack, controlplane.IncidentClosed, &closed)

	rep, err := srv.ResponseMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.DetectionLatency.P50; got != 600 {
		t.Errorf("detection latency p50 = %v, want 600s — this is the PLATFORM's lag and must not be "+
			"folded into the analyst's number", got)
	}
	if got := rep.TimeToAcknowledge.P50; got != 300 {
		t.Errorf("time-to-acknowledge p50 = %v, want 300s (measured from when the incident EXISTED, not "+
			"from the first alert — an analyst cannot ack an incident that has not been raised)", got)
	}
	if got := rep.TimeToResolve.P50; got != 2100 {
		t.Errorf("time-to-resolve p50 = %v, want 2100s", got)
	}
	if rep.TimeToResolve.Count != 1 || rep.TimeToAcknowledge.Count != 1 {
		t.Errorf("counts = ack %d resolve %d, want 1 each", rep.TimeToAcknowledge.Count, rep.TimeToResolve.Count)
	}
	if rep.TimeToAcknowledge.Mean != 300 {
		t.Errorf("mean = %v, want 300", rep.TimeToAcknowledge.Mean)
	}
}

// TestExcludedPopulationIsReported — the denominator is part of the measurement.
//
// MTTA covers only acknowledged incidents and MTTR only closed ones, and the selection is CORRELATED with
// what is measured: the incidents nobody got to are exactly the ones that would look worst. "MTTA 4
// minutes" over 3 of 200 incidents reads as fleet performance and is not.
//
// Mutation: report only the included count and drop `excluded` → FAILS.
func TestExcludedPopulationIsReported(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	created := now.Add(-time.Hour)
	ack := created.Add(time.Minute)
	closed := created.Add(2 * time.Minute)

	// One fully handled, three untouched, one acked-but-never-closed.
	seedTimedIncident(t, pool, "s-handled", created, created, &ack, controlplane.IncidentClosed, &closed)
	for _, s := range []string{"s-ignored-1", "s-ignored-2", "s-ignored-3"} {
		seedTimedIncident(t, pool, s, created, created, nil, controlplane.IncidentOpen, nil)
	}
	seedTimedIncident(t, pool, "s-acked-open", created, created, &ack, controlplane.IncidentAcknowledged, nil)

	rep, err := srv.ResponseMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Incidents != 5 {
		t.Fatalf("incidents = %d, want 5", rep.Incidents)
	}
	if rep.TimeToAcknowledge.Count != 2 || rep.TimeToAcknowledge.Excluded != 3 {
		t.Errorf("time-to-acknowledge count=%d excluded=%d, want 2 and 3 — an average that hides how many "+
			"incidents it leaves out is not a fleet measurement",
			rep.TimeToAcknowledge.Count, rep.TimeToAcknowledge.Excluded)
	}
	if rep.TimeToResolve.Count != 1 || rep.TimeToResolve.Excluded != 4 {
		t.Errorf("time-to-resolve count=%d excluded=%d, want 1 and 4 — a contained-or-open incident is not "+
			"resolved", rep.TimeToResolve.Count, rep.TimeToResolve.Excluded)
	}
	if rep.Incidents != rep.TimeToResolve.Count+rep.TimeToResolve.Excluded {
		t.Error("the resolve population does not add up to the incident count — some incidents are in " +
			"neither the measurement nor its exclusions")
	}
}

// TestMetricsHistogramsMoveAndAreWellFormed: the exposition is hand-written (PLAT-4 kept /metrics
// dependency-free), so nothing but a test enforces that buckets are cumulative and +Inf equals _count.
func TestMetricsHistogramsMoveAndAreWellFormed(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	created := now.Add(-time.Hour)

	scrape := func() string {
		rec := httptest.NewRecorder()
		srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		if rec.Code != 200 {
			t.Fatalf("scrape returned %d", rec.Code)
		}
		return rec.Body.String()
	}
	metricValue := func(body, series string) string {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, series+" ") {
				return strings.TrimSpace(strings.TrimPrefix(line, series))
			}
		}
		return ""
	}

	// A SECOND incident acknowledged after four days — above the top bucket. Without an observation
	// beyond the largest bound, the +Inf bucket and the last finite bucket are numerically identical and
	// a mutation swapping them is undetectable. (Found by running exactly that mutation and watching it
	// pass.) It is also a real case: nobody looked until after a long weekend.
	slowAck := created.Add(4 * 24 * time.Hour)
	seedTimedIncident(t, pool, "subject-soar6-slow", created.Add(-5*24*time.Hour), created, &slowAck,
		controlplane.IncidentAcknowledged, nil)

	id := seedTimedIncident(t, pool, "subject-soar6-hist", created, created, nil, controlplane.IncidentOpen, nil)
	before := scrape()
	if got := metricValue(before, "openshield_incident_time_to_acknowledge_seconds_count"); got != "1" {
		t.Fatalf("ack count starts at %q, want 1 (the slow-acked incident)", got)
	}
	if got := metricValue(before, "openshield_incident_time_to_acknowledge_seconds_excluded"); got != "1" {
		t.Errorf("excluded gauge = %q, want 1 — the unacknowledged incident is invisible", got)
	}

	if _, err := srv.AcknowledgeIncident(ctx, id, "cert:a"); err != nil {
		t.Fatal(err)
	}
	after := scrape()
	if got := metricValue(after, "openshield_incident_time_to_acknowledge_seconds_count"); got != "2" {
		t.Errorf("after an acknowledgement the count is %q, want 2 — the histogram does not move", got)
	}
	if got := metricValue(after, "openshield_incident_time_to_acknowledge_seconds_excluded"); got != "0" {
		t.Errorf("excluded gauge = %q, want 0 after the only incident was acked", got)
	}

	// Buckets: monotonic, and +Inf equals _count.
	name := "openshield_incident_time_to_acknowledge_seconds"
	prev := -1
	for _, le := range []string{"60", "300", "900", "1800", "3600", "14400", "43200", "86400", "259200"} {
		v := metricValue(after, name+`_bucket{le="`+le+`"}`)
		if v == "" {
			t.Fatalf("bucket le=%s missing", le)
		}
		n := atoiOrFail(t, v)
		if n < prev {
			t.Errorf("bucket le=%s is %d, below the previous %d — buckets must be CUMULATIVE", le, n, prev)
		}
		prev = n
	}
	// The observation above the top bound is what makes this assertion bite: the last finite bucket must
	// NOT equal +Inf here.
	if last := metricValue(after, name+`_bucket{le="259200"}`); last == metricValue(after, name+"_count") {
		t.Error("the fixture has no observation above the largest bucket, so the +Inf assertion below " +
			"cannot detect a wrong value")
	}
	inf := metricValue(after, name+`_bucket{le="+Inf"}`)
	count := metricValue(after, name+"_count")
	if inf != count {
		t.Errorf("+Inf bucket %q != _count %q — a malformed histogram silently misreports every quantile "+
			"a scraper derives from it", inf, count)
	}
	if metricValue(after, name+"_sum") == "" {
		t.Error("_sum missing — a scraper cannot compute an average without it")
	}

	// NO PER-OPERATOR SERIES. Grouping these by named analyst is trivial and deliberately not done:
	// attribution on an incident serves accountability; a per-person score is workforce surveillance.
	if strings.Contains(after, "cert:") || strings.Contains(after, `analyst="`) {
		t.Error("the metrics exposition names an operator — response times must stay fleet-level")
	}
}

func atoiOrFail(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// TestScrapeSurvivesAnUnavailableAggregate: a metrics endpoint that fails takes alerting down with it,
// turning a reporting problem into an outage in the system that would have reported the outage.
//
// Mutation: return a non-200 when the aggregate fails → FAILS.
func TestScrapeSurvivesAnUnavailableAggregate(t *testing.T) {
	// A server with no database: the counters half needs none and must keep serving.
	srv := controlplane.New(nil)
	rec := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("a scrape with no usable aggregate returned %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "openshield_decode_failures_total") {
		t.Error("the counters were not served — a failing aggregate suppressed the metrics that alerts fire on")
	}
	if !strings.Contains(body, "response metrics unavailable") {
		t.Error("the omission is silent — an operator cannot tell missing metrics from a healthy zero")
	}
	if strings.Contains(body, "time_to_acknowledge_seconds_count") {
		t.Error("a histogram was emitted without an aggregate behind it")
	}
}

// TestResponseReportEndpoint serves the analyst-readable form, with no operator in it.
func TestResponseReportEndpoint(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	now := time.Now().UTC()
	created := now.Add(-time.Hour)
	ack := created.Add(90 * time.Second)
	seedTimedIncident(t, pool, "subject-soar6-report", created, created, &ack, controlplane.IncidentAcknowledged, nil)

	rec := httptest.NewRecorder()
	srv.OperatorReadHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/report/response", nil))
	if rec.Code != 200 {
		t.Fatalf("report returned %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"detection_latency", "time_to_acknowledge", "time_to_resolve", "excluded"} {
		if !strings.Contains(body, want) {
			t.Errorf("report is missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "cert:") {
		t.Error("the report names an operator — response metrics stay fleet-level by design")
	}
}
