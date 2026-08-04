package controlplane_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// SOAR-9b — ESCALATION LADDERS.
//
// SOAR-9 decided WHERE a notification goes at the moment it is raised. Nothing decided what happens when
// it goes there and nobody answers. That is the failure alerting systems actually die of: the page is
// delivered, the delivery is recorded a success, and the incident sits open. Every part of the machine
// reports that it worked.

// seedOpenIncident inserts an open incident raised `age` ago, at a given risk (which fixes its severity).
func seedOpenIncident(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	subject string, risk float64, age time.Duration) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count,
		                        first_seen, last_seen, created_at)
		 VALUES ('ueba_burst',$1,'open',3,$2,1,now(),now(),$3) RETURNING id`,
		subject, risk, time.Now().UTC().Add(-age)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func ladder(t *testing.T, body string, sinks ...string) controlplane.Ladder {
	t.Helper()
	l, err := controlplane.LoadLadder(strings.NewReader(body), sinks)
	if err != nil {
		t.Fatalf("loading ladder: %v", err)
	}
	return l
}

// THE HEADLINE: an incident nobody acknowledged escalates, and acknowledging it stops the ladder dead.
//
// Mutation (drop `state = 'open'` from the candidate query): the acknowledged incident escalates too →
// FAIL. That filter IS the acknowledgement check — there is no separate cancel step to forget to call.
func TestAnUnacknowledgedIncidentEscalatesAndAnAcknowledgedOneDoesNot(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	ignored := seedOpenIncident(t, ctx, pool, "sub_esc_ignored", 0.95, 30*time.Minute)
	handled := seedOpenIncident(t, ctx, pool, "sub_esc_handled", 0.95, 30*time.Minute)
	if _, err := srv.AcknowledgeIncident(ctx, handled, "cert:alice"); err != nil {
		t.Fatal(err)
	}

	l := ladder(t, `{"rungs":[{"after_seconds":600,"sinks":["pager"]}]}`, "pager")
	n, err := srv.Escalate(ctx, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("escalated %d incident(s), want exactly 1 — the acknowledged one must be out of scope, "+
			"and an escalation that fires anyway teaches responders that acknowledging does nothing", n)
	}
	waitFor(t, func() bool { return hook.count() >= 1 })

	got := hook.snapshot()[0]
	if got.Kind != notify.KindEscalation {
		t.Errorf("escalation kind = %q, want %q — routing keys on kind, so a re-send of the ORIGINAL "+
			"kind goes exactly where the page nobody answered went", got.Kind, notify.KindEscalation)
	}
	if got.Subject != "sub_esc_ignored" {
		t.Errorf("escalated subject = %q, want the UNACKNOWLEDGED incident's", got.Subject)
	}
	if !strings.Contains(got.Detail, fmt.Sprint(ignored)) {
		t.Errorf("escalation detail %q does not name the incident it is about", got.Detail)
	}
}

// A RUNG FIRES AT MOST ONCE, INCLUDING ACROSS A RESTART.
//
// The sweep runs on a clock, so an incident that stays open is a candidate on every single tick. Without
// a durable record of which rung it has climbed, the ladder built to get attention becomes the thing
// that guarantees the pager gets muted — and a restart or leader handover would re-fire every rung of
// every open incident at once.
//
// Mutation (send first and record after, or drop the ON CONFLICT DO NOTHING claim): the repeat sweeps
// fire again → FAIL.
func TestARungFiresOnceNoMatterHowOftenTheSweepRuns(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	seedOpenIncident(t, ctx, pool, "sub_esc_once", 0.95, time.Hour)
	l := ladder(t, `{"rungs":[{"after_seconds":600,"sinks":["pager"]}]}`, "pager")

	if n, _ := srv.Escalate(ctx, l, now); n != 1 {
		t.Fatalf("first sweep escalated %d, want 1", n)
	}
	waitFor(t, func() bool { return hook.count() >= 1 })

	// Five more sweeps, exactly as the loop would run them — including the ones a restarted process
	// would run against the same still-open incident.
	for i := 0; i < 5; i++ {
		if n, err := srv.Escalate(ctx, l, now.Add(time.Duration(i)*time.Minute)); err != nil || n != 0 {
			t.Fatalf("sweep %d escalated %d, %v; want 0 — a rung already climbed must not re-fire",
				i+2, n, err)
		}
	}
	time.Sleep(300 * time.Millisecond) // give any stray delivery time to land
	if c := hook.count(); c != 1 {
		t.Fatalf("%d escalation pages for one rung, want 1 — this is how an escalation mechanism "+
			"trains people to mute it", c)
	}
}

// THE LADDER CLIMBS: a later rung fires when its own, longer deadline passes.
//
// Mutation A (drop the per-rung deadline check, leaving only the SQL bound that admitted the incident):
// all three rungs fire at 45 minutes → FAIL. The SQL bound is the widest one — it exists to keep the
// scan small, not to decide anything — so without the per-rung check an incident that clears the FIRST
// deadline immediately climbs the whole ladder, and a three-rung ladder becomes a one-rung one that
// pages the director.
//
// Mutation B (use one notification id per incident instead of per rung): the second rung is delivered
// under the first's idempotency key → FAIL on the distinct-id assertion.
func TestALaterRungFiresWhenItsOwnDeadlinePasses(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	seedOpenIncident(t, ctx, pool, "sub_esc_climb", 0.95, 45*time.Minute)
	l := ladder(t, `{"rungs":[
	     {"after_seconds":600,"sinks":["pager"]},
	     {"after_seconds":1800,"sinks":["manager"]},
	     {"after_seconds":7200,"sinks":["director"]}
	   ]}`, "pager", "manager", "director")

	n, err := srv.Escalate(ctx, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("fired %d rungs at 45 minutes, want 2 — rungs at 10m and 30m are due, the 2h one is "+
			"not", n)
	}
	waitFor(t, func() bool { return hook.count() >= 2 })

	// Distinct idempotency keys, or a receiver deduping on ID swallows the second rung as a retry of
	// the first — the escalation would be delivered by us and discarded by them.
	ids := map[string]bool{}
	for _, g := range hook.snapshot() {
		ids[g.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("two rungs shared %d distinct notification id(s), want 2 — a receiver deduping on id "+
			"would treat the second rung as a retry of the first and drop it", len(ids))
	}
}

// A RUNG'S SEVERITY FLOOR IS HONOURED.
//
// Mutation (ignore MinSeverity): the low-severity incident escalates to the director → FAIL. A ladder
// that escalates everything to everyone is the muted-pager outcome reached by a different route.
func TestARungSeverityFloorIsHonoured(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seedOpenIncident(t, ctx, pool, "sub_esc_low", 0.10, time.Hour)  // low
	seedOpenIncident(t, ctx, pool, "sub_esc_crit", 0.99, time.Hour) // critical

	l := ladder(t, `{"rungs":[{"after_seconds":600,"min_severity":"critical","sinks":["pager"]}]}`, "pager")
	n, err := srv.Escalate(ctx, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("escalated %d, want 1 — only the critical incident clears a critical floor", n)
	}
}

// AN INCIDENT YOUNGER THAN THE FIRST RUNG DOES NOT ESCALATE.
//
// Mutation (drop the `created_at <=` bound, or compare with > instead of <): a two-minute-old incident
// escalates against a ten-minute deadline → FAIL. The deadline is the entire feature; firing early is
// not a conservative choice, it is the feature not existing.
func TestAnIncidentInsideItsDeadlineIsNotEscalated(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seedOpenIncident(t, ctx, pool, "sub_esc_fresh", 0.99, 2*time.Minute)
	l := ladder(t, `{"rungs":[{"after_seconds":600,"sinks":["pager"]}]}`, "pager")
	n, err := srv.Escalate(ctx, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("escalated %d incident(s) inside the deadline, want 0", n)
	}
}

// LOAD VALIDATION REFUSES THE LADDERS THAT WOULD FAIL SILENTLY.
//
// Each of these, accepted, produces a ladder that runs and does the wrong thing — which is discovered by
// a page that did not arrive, weeks later, during an incident.
func TestABadLadderIsRefusedAtLoadNotAtFiringTime(t *testing.T) {
	for _, tc := range []struct{ name, body, why string }{
		{"no sinks", `{"rungs":[{"after_seconds":600,"sinks":[]}]}`,
			"a rung with no sinks silently discards exactly what it matched"},
		{"no deadline", `{"rungs":[{"after_seconds":0,"sinks":["pager"]}]}`,
			"a rung with no deadline fires against every open incident immediately"},
		{"out of order", `{"rungs":[{"after_seconds":1800,"sinks":["pager"]},{"after_seconds":600,"sinks":["pager"]}]}`,
			"a ladder whose second rung fires before its first is a typo, and silently sorting it would run a ladder the operator did not write"},
		{"unknown sink", `{"rungs":[{"after_seconds":600,"sinks":["nowhere"]}]}`,
			"a rung naming an unconfigured sink escalates into nothing"},
		{"not a severity", `{"rungs":[{"after_seconds":600,"min_severity":"urgent","sinks":["pager"]}]}`,
			"an unknown severity floor matches nothing, so the rung never fires"},
		{"unknown field", `{"rungs":[{"after_seconds":600,"sinks":["pager"],"on_call":"alice"}]}`,
			"a field this product does not implement must not be accepted as if it worked — that is how a rotation nobody built gets relied on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := controlplane.LoadLadder(strings.NewReader(tc.body), []string{"pager"}); err == nil {
				t.Fatalf("accepted a ladder that should be refused: %s", tc.why)
			}
		})
	}

	// And a well-formed one loads, so the refusals above are not simply "nothing is ever accepted".
	l, err := controlplane.LoadLadder(strings.NewReader(
		`{"rungs":[{"after_seconds":600,"min_severity":"high","sinks":["pager"]}]}`), []string{"pager"})
	if err != nil {
		t.Fatalf("a valid ladder was refused: %v", err)
	}
	if len(l.Rungs) != 1 || l.Rungs[0].After != 10*time.Minute {
		t.Fatalf("loaded ladder = %+v, want one rung at 10m (after_seconds must be decoded into After, "+
			"or every deadline is zero and every rung fires immediately)", l.Rungs)
	}
}
