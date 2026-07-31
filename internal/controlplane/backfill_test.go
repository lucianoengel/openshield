package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// SOAR-10 — CORRELATION BACKFILL.
//
// Correlation runs over a look-back window on a clock. Alerts outside it are never correlated — and the
// ones that matter most are exactly the ones that fell outside because correlation was NOT RUNNING: a
// leader outage, an interval left at zero, a deployment gap. Those alerts sit in the store forever,
// individually visible and never joined, and the incident that should have paged somebody does not exist.
// Nothing reports its absence, because nothing knows it was supposed to be there.

// THE HEADLINE: alerts too old for the live window produce an incident when the range is replayed.
//
// Mutation (step the window by anything other than the window itself, or drop the loop and call the
// materializer once at `to`): the old burst is outside every look-back that runs → FAIL.
func TestABurstOlderThanTheLiveWindowIsCorrelatedByBackfill(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_bf_%d", now.UnixNano())

	// A burst three days ago — far outside any live one-hour window.
	old := now.Add(-72 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'v1','agent-a',$3)`, subject, 0.9, old.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}

	// The live loop, running now, sees nothing: the alerts are three days outside its window.
	if n, err := srv.MaterializeIncidents(ctx, rule, now); err != nil || n != 0 {
		t.Fatalf("the LIVE materializer produced %d incident(s) (%v); it must see nothing, or this "+
			"test proves nothing about backfill", n, err)
	}

	res, err := srv.Backfill(ctx, rule, cross, now.Add(-96*time.Hour), now)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Burst < 1 {
		t.Fatalf("backfill over four days raised %d burst incident(s) across %d step(s), want >=1 — "+
			"alerts that fell outside the window because correlation was NOT RUNNING are exactly the "+
			"ones nothing else will ever join", res.Burst, res.Steps)
	}

	found := false
	all, err := srv.RecentIncidents(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range all {
		if i.SubjectID == subject {
			found = true
		}
	}
	if !found {
		t.Fatal("the backfilled incident is not in the store")
	}
}

// A BACKFILLED INCIDENT DOES NOT PAGE.
//
// A month of backfill would page the SOC for hundreds of incidents that are long over, at which point the
// pager is muted — and the next LIVE incident is muted with it. The evidence is written; the alarm is not
// rung for something nobody can respond to any more.
//
// Mutation (drop the quiet() guard in the materializers): the webhook receives the backfilled incident →
// FAIL.
func TestBackfilledIncidentsAreRecordedAndNotPaged(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_bfquiet_%d", now.UnixNano())

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	old := now.Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,0.9,'v1','agent-a',$2)`, subject, old.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}

	res, err := srv.Backfill(ctx, rule, cross, now.Add(-72*time.Hour), now)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Burst < 1 {
		t.Fatalf("the backfill raised nothing (%d), so 'it did not page' proves nothing", res.Burst)
	}
	time.Sleep(400 * time.Millisecond) // give any stray delivery time to land
	if c := hook.count(); c != 0 {
		t.Fatalf("a backfill delivered %d page(s) — replaying a month of history would mute the pager, "+
			"and the next LIVE incident with it", c)
	}

	// AND PAGING IS RESTORED. A suppression that outlives its run is worse than the noise it prevented:
	// the product would be silently un-alerted from then on.
	live := fmt.Sprintf("sub_bflive_%d", now.UnixNano())
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,0.9,'v1','agent-a',$2)`, live, now.Add(-time.Duration(i+1)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return hook.count() >= 1 })
}

// A BACKFILLED INCIDENT IS MARKED, AND EXCLUDED FROM THE RESPONSE METRICS.
//
// Its created_at is when the backfill ran, so its detection latency is the AGE OF THE ALERT and its
// time-to-acknowledge starts from a moment no analyst could have acted on. Averaged in with real
// incidents, one backfill would move the fleet's measured response arbitrarily far in either direction
// depending only on how far back somebody reached.
//
// Mutation (drop `WHERE NOT backfilled` from ResponseMetrics): the incident count rises and the
// three-day-old detection latency lands in the average → FAIL.
func TestABackfilledIncidentIsExcludedFromResponseMetrics(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_bfmetrics_%d", now.UnixNano())

	before, err := srv.ResponseMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}

	old := now.Add(-72 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,0.9,'v1','agent-a',$2)`, subject, old.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}
	res, err := srv.Backfill(ctx, rule, cross, now.Add(-96*time.Hour), now)
	if err != nil || res.Burst < 1 {
		t.Fatalf("backfill raised %d (%v); this test needs at least one", res.Burst, err)
	}

	// The flag is set.
	var backfilled bool
	if err := pool.QueryRow(ctx,
		`SELECT backfilled FROM incidents WHERE subject_id = $1`, subject).Scan(&backfilled); err != nil {
		t.Fatal(err)
	}
	if !backfilled {
		t.Fatal("the incident is not marked backfilled — an operator reading it has no way to know its " +
			"timestamps do not mean what they usually do")
	}

	after, err := srv.ResponseMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Incidents != before.Incidents {
		t.Fatalf("the response report counts %d incidents, up from %d — a backfilled incident's "+
			"created_at is when the BACKFILL ran, so its detection latency is the age of the alert and "+
			"its MTTA starts from a moment no analyst could have acted on",
			after.Incidents, before.Incidents)
	}
	if after.DetectionLatency.Excluded != before.DetectionLatency.Excluded {
		t.Errorf("the backfilled incident was counted as EXCLUDED (%d, was %d) — 'excluded' means an "+
			"incident that COULD have contributed and did not, which is a statement about the response "+
			"process. A backfilled one was never part of that process",
			after.DetectionLatency.Excluded, before.DetectionLatency.Excluded)
	}
}

// A LIVE INCIDENT IS NOT RELABELLED BY A BACKFILL THAT RUNS AFTER IT.
//
// The marking pass is scoped by created_at. Scoped wrongly, a backfill would flag incidents raised live
// moments earlier — and since backfilled incidents are excluded from the response metrics, that would
// silently delete real incidents from the fleet's measured performance.
//
// Mutation (mark every open incident, or scope the UPDATE by the backfill's `to` instead of its start):
// the live incident is flagged → FAIL.
func TestABackfillDoesNotRelabelIncidentsRaisedLive(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	live := fmt.Sprintf("sub_bfnotmine_%d", now.UnixNano())

	// An incident raised LIVE, right now.
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,0.9,'v1','agent-a',$2)`, live, now.Add(-time.Duration(i+1)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}
	if n, err := srv.MaterializeIncidents(ctx, rule, now); err != nil || n != 1 {
		t.Fatalf("live materialize = %d, %v; want 1", n, err)
	}

	// A backfill over a range that ENDED before that incident was created.
	if _, err := srv.Backfill(ctx, rule, cross, now.Add(-96*time.Hour), now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var backfilled bool
	if err := pool.QueryRow(ctx,
		`SELECT backfilled FROM incidents WHERE subject_id = $1`, live).Scan(&backfilled); err != nil {
		t.Fatal(err)
	}
	if backfilled {
		t.Fatal("a backfill flagged an incident raised LIVE — and because backfilled incidents are " +
			"excluded from the response metrics, that silently deletes real incidents from the fleet's " +
			"measured performance")
	}
}

// AN UNUSABLE RANGE IS REFUSED, INCLUDING ONE THAT IS MERELY ENORMOUS.
//
// "Since 1970 with a one-minute window" is a plausible typo that would run half a million steps against
// the database the live pipeline is using. Truncating it silently would report success over a range it
// did not cover — the same shape as the gap the job exists to close.
//
// Mutation (drop the maxBackfillSteps check): the enormous range is accepted → FAIL (or hangs, which the
// test's own timeout catches).
func TestAnUnusableBackfillRangeIsRefused(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := controlplane.CrossDomainRule{Window: time.Hour, MinDomains: 2}

	if _, err := srv.Backfill(ctx, rule, cross, now, now.Add(-time.Hour)); !errors.Is(err, controlplane.ErrBadRange) {
		t.Errorf("an inverted range = %v, want ErrBadRange", err)
	}
	if _, err := srv.Backfill(ctx, rule, cross, now, now); !errors.Is(err, controlplane.ErrBadRange) {
		t.Errorf("an empty range = %v, want ErrBadRange", err)
	}
	tiny := controlplane.CorrelationRule{Window: time.Minute, MinAlerts: 3}
	if _, err := srv.Backfill(ctx, tiny, cross, now.Add(-365*24*time.Hour), now); !errors.Is(err, controlplane.ErrBadRange) {
		t.Errorf("a year at a one-minute step = %v, want ErrBadRange — half a million steps against the "+
			"live database, and truncating it silently would report success over a range it did not "+
			"cover", err)
	}
}
