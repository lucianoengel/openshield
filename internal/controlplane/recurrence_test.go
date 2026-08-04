package controlplane_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// SOAR-2b — INCIDENT RECURRENCE.
//
// The README's SOAR gap said "no incident reopen". Reopen as a lifecycle TRANSITION is refused here and
// still is (D250: MTTA/MTTR are derived from a monotone timeline), so the honest reading of that gap is
// not "we cannot move an incident backwards" — it is that when the same trouble came back after a close,
// the new incident had no connection to the old one and arrived on the pager looking like first-time
// trouble. These tests are about that connection.

// recurSeed inserts a peer alert for one subject.
func recurSeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject string,
	risk float64, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
		 VALUES ($1,$2,'v1','agent-a',$3)`, subject, risk, at); err != nil {
		t.Fatal(err)
	}
}

// closeIncident advances an incident all the way to closed, which is what a responder does when they
// believe the matter is finished. That belief is exactly what a recurrence contradicts.
func closeIncident(t *testing.T, ctx context.Context, srv *controlplane.Server, id int64) {
	t.Helper()
	if err := srv.TransitionIncident(ctx, id, controlplane.IncidentClosed, "cert:alice"); err != nil {
		t.Fatalf("closing incident %d: %v", id, err)
	}
}

// openIncidentFor returns the subject's single open incident, failing if there is not exactly one.
func openIncidentFor(t *testing.T, ctx context.Context, srv *controlplane.Server,
	subject string) controlplane.StoredIncident {
	t.Helper()
	all, err := srv.RecentIncidents(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	var found []controlplane.StoredIncident
	for _, i := range all {
		if i.SubjectID == subject && i.State == controlplane.IncidentOpen {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		t.Fatalf("open incidents for %s = %d, want exactly 1", subject, len(found))
	}
	return found[0]
}

// THE HEADLINE: trouble that comes back after a close is LINKED to what it came back from, and counted.
//
// Mutation (drop the linkRecurrence call, or link on the DO UPDATE path instead of the insert path):
// the second incident's RecurrenceOf is 0 and its count stays 0 → this FAILs on the first assertion.
func TestAnIncidentRaisedAfterACloseIsLinkedToTheOneItRecursFrom(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_%d", now.UnixNano())

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	burst := func() {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}

	burst()
	first := openIncidentFor(t, ctx, srv, subject)
	if first.RecurrenceCount != 0 || first.RecurrenceOf != 0 {
		t.Fatalf("the FIRST occurrence claims to be a recurrence (of=%d count=%d) — every incident "+
			"would then look like a repeat and the signal would mean nothing",
			first.RecurrenceOf, first.RecurrenceCount)
	}

	closeIncident(t, ctx, srv, first.ID)
	burst()
	second := openIncidentFor(t, ctx, srv, subject)

	if second.ID == first.ID {
		t.Fatal("the second burst reused the closed incident — the lifecycle is forward-only and a " +
			"closed incident must never come back to open")
	}
	if second.RecurrenceOf != first.ID {
		t.Fatalf("recurrence_of = %d, want %d — without the link an operator looking at incident %d "+
			"cannot tell whether this is new trouble or the second time someone closed the same thing, "+
			"and those warrant opposite responses", second.RecurrenceOf, first.ID, second.ID)
	}
	if second.RecurrenceCount != 1 {
		t.Fatalf("recurrence_count = %d, want 1", second.RecurrenceCount)
	}

	// And it accumulates: close the second, let it come back again.
	closeIncident(t, ctx, srv, second.ID)
	burst()
	third := openIncidentFor(t, ctx, srv, subject)
	if third.RecurrenceOf != second.ID || third.RecurrenceCount != 2 {
		t.Fatalf("third occurrence: of=%d count=%d, want of=%d count=2 — the count must be the "+
			"predecessor's plus one, not a flag that says 'seen before'",
			third.RecurrenceOf, third.RecurrenceCount, second.ID)
	}
}

// A RECURRENCE IS SCOPED TO THE SAME SUBJECT.
//
// The predecessor lookup asks "the most recent closed incident of this kind" and then narrows it to the
// subject. Lose the narrowing and every incident becomes a recurrence of whatever the SOC closed last,
// which is worse than having no link at all: it is a confident, wrong statement that two unrelated
// things are the same trouble coming back, printed on the page that decides how they get triaged.
//
// Mutation (drop `subject_id = $3` from the predecessor query): the unrelated closed incident is adopted
// → this FAILs.
func TestARecurrenceIsScopedToTheSubjectItRecursFor(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	stamp := now.UnixNano()
	other := fmt.Sprintf("sub_recur_other_%d", stamp)
	mine := fmt.Sprintf("sub_recur_mine_%d", stamp)

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	burst := func(subject string) {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}

	// Somebody else's incident, closed a moment ago — the most recent closed incident in the table.
	burst(other)
	closeIncident(t, ctx, srv, openIncidentFor(t, ctx, srv, other).ID)

	// A first-ever incident for a different subject is NOT a recurrence of it.
	burst(mine)
	inc := openIncidentFor(t, ctx, srv, mine)
	if inc.RecurrenceOf != 0 || inc.RecurrenceCount != 0 {
		t.Fatalf("a first-ever incident for %s was linked to another subject's closed incident "+
			"(of=%d count=%d) — a wrong link is worse than no link: it asserts that two unrelated "+
			"things are the same trouble returning, on the page that decides how both get handled",
			mine, inc.RecurrenceOf, inc.RecurrenceCount)
	}
}

// RE-CORRELATING AN ONGOING BURST DOES NOT MOVE THE COUNT.
//
// Correlation runs on a clock, so an unresolved incident is re-materialized every tick. Stated as an
// invariant rather than as a mutation kill, because it is honestly over-determined: the link is
// established only on the INSERT path, and even if it were not, recomputing it from the predecessor's
// count is idempotent. Both facts have to hold; this asserts the observable consequence of the pair, so
// losing either one alone stays silent here and losing both does not.
func TestReCorrelatingAnOngoingBurstDoesNotMoveTheCount(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_open_%d", now.UnixNano())

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	burst := func() {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}

	burst()
	closeIncident(t, ctx, srv, openIncidentFor(t, ctx, srv, subject).ID)
	burst()
	second := openIncidentFor(t, ctx, srv, subject)
	if second.RecurrenceCount != 1 {
		t.Fatalf("recurrence_count = %d, want 1 before the extra ticks", second.RecurrenceCount)
	}

	for tick := 0; tick < 4; tick++ {
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}
	after := openIncidentFor(t, ctx, srv, subject)
	if after.ID != second.ID || after.RecurrenceOf != second.RecurrenceOf || after.RecurrenceCount != 1 {
		t.Fatalf("after four more correlation ticks over the SAME open incident: id=%d of=%d count=%d, "+
			"want id=%d of=%d count=1 — an unresolved incident must not climb the recurrence count "+
			"simply by staying unresolved while the clock runs",
			after.ID, after.RecurrenceOf, after.RecurrenceCount, second.ID, second.RecurrenceOf)
	}
}

// A PREDECESSOR OLDER THAN THE WINDOW IS NOT A PREDECESSOR.
//
// Without a bound, the first incident a long-lived subject ever had becomes the ancestor of every
// incident it has years later, and "recurrence #37" degrades into "this subject has been around a
// while" — a number that looks like a finding and is not one.
//
// Mutation (drop the `last_seen >= cutoff` clause): the ancient incident is adopted as the predecessor
// → this FAILs.
func TestAPredecessorOutsideTheWindowIsNotARecurrence(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_old_%d", now.UnixNano())

	rule := controlplane.CorrelationRule{Window: 400 * 24 * time.Hour, MinAlerts: 3,
		RecurrenceWindow: 24 * time.Hour}

	// An incident from a year ago, closed.
	long := now.Add(-365 * 24 * time.Hour)
	for i, extra := range []time.Duration{0, time.Minute, 2 * time.Minute} {
		recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, long.Add(extra))
	}
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	old := openIncidentFor(t, ctx, srv, subject)
	closeIncident(t, ctx, srv, old.ID)

	// Trouble today. It is NOT a recurrence of something a year old.
	for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
	}
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	fresh := openIncidentFor(t, ctx, srv, subject)
	if fresh.RecurrenceOf != 0 || fresh.RecurrenceCount != 0 {
		t.Fatalf("an incident a YEAR old was adopted as the predecessor (of=%d count=%d) — with no "+
			"bound, the recurrence count stops being a statement about a recurrence and becomes one "+
			"about how long the subject has existed", fresh.RecurrenceOf, fresh.RecurrenceCount)
	}
}

// THE CHAIN IS REACHABLE FROM ANY MEMBER, NOT ONLY THE NEWEST.
//
// An operator arrives holding whichever id a case, a ticket or an old notification recorded. A chain
// reachable only from its head would be unreachable from exactly the places people enter it.
//
// Mutation (walk only backwards from the requested id): asking from the OLDEST member returns 1 instead
// of 3 → this FAILs.
func TestTheRecurrenceChainIsReachableFromAnyMember(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_chain_%d", now.UnixNano())

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	var ids []int64
	for round := 0; round < 3; round++ {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
		inc := openIncidentFor(t, ctx, srv, subject)
		ids = append(ids, inc.ID)
		closeIncident(t, ctx, srv, inc.ID)
	}

	for _, from := range ids {
		chain, err := srv.RecurrenceChain(ctx, from)
		if err != nil {
			t.Fatalf("chain from %d: %v", from, err)
		}
		if len(chain) != 3 {
			t.Fatalf("chain from %d has %d members, want 3 — the chain must read the same from "+
				"whichever incident the operator happened to be handed", from, len(chain))
		}
		for i, got := range chain {
			if got.ID != ids[i] {
				t.Fatalf("chain from %d: position %d is incident %d, want %d (oldest first)",
					from, i, got.ID, ids[i])
			}
		}
	}

	// A lone incident is a chain of one, not an error: "this has happened once" is an answer.
	solo := fmt.Sprintf("sub_recur_solo_%d", now.UnixNano())
	for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		recurSeed(t, ctx, pool, solo, 0.8+float64(i)*0.05, now.Add(-ago))
	}
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	one := openIncidentFor(t, ctx, srv, solo)
	chain, err := srv.RecurrenceChain(ctx, one.ID)
	if err != nil || len(chain) != 1 {
		t.Fatalf("solo chain = %d members, %v; want 1 and no error", len(chain), err)
	}
}

// THE PAGE SAYS IT CAME BACK.
//
// The link is only worth having where the decision is made, and that is the notification. Two incidents
// that read identically get triaged identically — so a recurrence that pages with the same words as a
// first occurrence has recorded the fact and delivered none of it.
//
// Mutation (drop recurrenceSuffix from the Detail): the second page is byte-identical in wording to the
// first → this FAILs on the missing "RECURRENCE".
func TestARecurrencePagesDifferentlyFromAFirstOccurrence(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_page_%d", now.UnixNano())

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	burst := func() {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}

	burst()
	waitFor(t, func() bool { return hook.count() >= 1 })
	if d := hook.snapshot()[0].Detail; strings.Contains(d, "RECURRENCE") {
		t.Fatalf("the FIRST page announced a recurrence: %q", d)
	}

	closeIncident(t, ctx, srv, openIncidentFor(t, ctx, srv, subject).ID)
	burst()
	waitFor(t, func() bool { return hook.count() >= 2 })

	second := hook.snapshot()[1].Detail
	if !strings.Contains(second, "RECURRENCE #1") {
		t.Fatalf("the recurrence pages as %q — it is indistinguishable from first-time trouble, so "+
			"the responder who closed this an hour ago gets no hint that closing it did not work",
			second)
	}
}

// THE ENDPOINT IS ACTUALLY MOUNTED, AND BEHIND THE ANALYST GATE.
//
// A handler is not a feature until something routes to it. This drives the real role-gated server over
// TLS with a real client certificate, which is the only way to catch the failure mode where the function
// exists, its unit tests pass, and no request can ever reach it — the exact shape of the unwired-code
// defects this project has found repeatedly.
//
// Mutation A (drop the mux.HandleFunc registration): the request 404s → FAIL.
// Mutation B (drop the requireTier entry): the agent certificate below is served instead of refused → FAIL.
func TestTheRecurrenceEndpointIsMountedAndGated(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_recur_http_%d", now.UnixNano())

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	burst := func() {
		for i, ago := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
			recurSeed(t, ctx, pool, subject, 0.8+float64(i)*0.05, now.Add(-ago))
		}
		if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
			t.Fatal(err)
		}
	}
	burst()
	first := openIncidentFor(t, ctx, srv, subject)
	closeIncident(t, ctx, srv, first.ID)
	burst()
	second := openIncidentFor(t, ctx, srv, subject)

	op := clientWith(t, ca, "alice", "operator")
	resp, err := op.Get("https://" + addr + "/incidents/recurrences?id=" + itoa(second.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /incidents/recurrences = %d, want 200 — the chain is unreachable, which is a "+
			"handler with tests and no route", resp.StatusCode)
	}
	var got struct {
		Occurrences int                           `json:"occurrences"`
		Chain       []controlplane.StoredIncident `json:"chain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Occurrences != 2 || len(got.Chain) != 2 {
		t.Fatalf("occurrences=%d chain=%d, want 2 and 2", got.Occurrences, len(got.Chain))
	}
	if got.Chain[0].ID != first.ID || got.Chain[1].ID != second.ID {
		t.Fatalf("chain = [%d %d], want [%d %d] oldest first",
			got.Chain[0].ID, got.Chain[1].ID, first.ID, second.ID)
	}
	if got.Chain[1].RecurrenceCount != 1 {
		t.Errorf("the API omits recurrence_count (got %d, want 1) — the fact is stored and not served",
			got.Chain[1].RecurrenceCount)
	}

	// An agent identity is not an analyst.
	agent := clientWith(t, ca, "agent-1", "agent")
	resp2, err := agent.Get("https://" + addr + "/incidents/recurrences?id=" + itoa(second.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatalf("an agent certificate read the recurrence chain (%d) — incident history is analyst "+
			"surface, and an enrolled endpoint must not be able to enumerate the SOC's caseload",
			resp2.StatusCode)
	}
}
