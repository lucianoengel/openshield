package controlplane_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// TestTwoHuntsOnOneEntityRaiseTwoIncidentsAndPageTwice (XDR-4c).
//
// Before rule_name joined the conflict targets, two hunts matching one entity shared
// kind='cross_domain' and therefore shared BOTH unique indexes. The second materialization took the
// DO UPDATE path, overwrote the first hunt's counts with its own narrower ones, and — because only a
// genuine INSERT pages (SOAR-1/D220) — never paged at all. A second, different attack narrative on the
// same asset was silently folded into the first one's incident, and every subsequent tick the row
// flip-flopped between whichever hunts still matched.
//
// Mutation: drop rule_name from incidents_open_entity_idx and from the ON CONFLICT target → the second
// hunt takes DO UPDATE → the incident count is 1 and the page count is 1 → FAILS.
func TestTwoHuntsOnOneEntityRaiseTwoIncidentsAndPageTwice(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &countingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()
	now := time.Now().UTC()

	// One asset evidencing TWO distinct narratives: a credential staged then exfiltrated (T1552 →
	// T1567.002) and a LOLBin followed by an obfuscated command (T1218 → T1027).
	subject := pseudonym.Of("agent-xdr4c-two-hunts")
	recordTechAlert(t, srv, "dlp", subject, now.Add(-8*time.Minute), "T1552")
	recordTechAlert(t, srv, "hips", subject, now.Add(-6*time.Minute), "T1218")
	recordTechAlert(t, srv, "nips", subject, now.Add(-4*time.Minute), "T1567.002")
	recordTechAlert(t, srv, "hips", subject, now.Add(-2*time.Minute), "T1027")
	entity := entityOf(t, srv, subject)

	hunts := []controlplane.CrossDomainRule{
		{Name: "credential-staged-then-exfiltrated", Window: 15 * time.Minute, MinDomains: 2,
			TechniqueSequence: []string{"T1552", "T1567.002"}},
		{Name: "lolbin-then-obfuscated-command", Window: 15 * time.Minute, MinDomains: 2,
			TechniqueSequence: []string{"T1218", "T1027"}},
	}
	for _, h := range hunts {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, h, now); err != nil {
			t.Fatalf("materialize %s: %v", h.Name, err)
		}
	}

	var got []string
	rows, err := pool.Query(ctx,
		`SELECT rule_name FROM incidents WHERE entity_id=$1 AND kind='cross_domain' AND state='open'
		  ORDER BY rule_name`, entity)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	if len(got) != 2 {
		t.Fatalf("open cross-domain incidents for entity %d = %v, want one per hunt — two narratives "+
			"folded into one incident means the second is invisible to the operator", entity, got)
	}
	if got[0] != "credential-staged-then-exfiltrated" || got[1] != "lolbin-then-obfuscated-command" {
		t.Fatalf("incident rule names = %v, want both hunts named", got)
	}
	if sink.count() != 2 {
		t.Errorf("paged %d time(s), want 2 — a hunt that raises an incident nobody is paged about is "+
			"the interactive-only behaviour this ticket exists to close", sink.count())
	}

	// Re-running the same hunts must CONVERGE, not duplicate: the page-once mechanism is per (entity,
	// rule), so a scheduled loop does not re-page every tick.
	for _, h := range hunts {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, h, now); err != nil {
			t.Fatalf("re-materialize %s: %v", h.Name, err)
		}
	}
	var open int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE entity_id=$1 AND kind='cross_domain' AND state='open'`,
		entity).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 2 {
		t.Errorf("open incidents after re-materialization = %d, want 2 — a re-run must extend, not duplicate", open)
	}
	if sink.count() != 2 {
		t.Errorf("paged %d time(s) after re-materialization, want still 2 — every tick re-paging an "+
			"incident a human already saw is what the xmax=0 check exists to prevent", sink.count())
	}
}

// The breadth rule keeps its identity alongside the hunts: it is strictly WIDER than any sequence rule,
// so replacing it with hunts would lose the case a hunt cannot anticipate — three domains lighting up
// in a shape nobody wrote a rule for.
func TestTheUnnamedBreadthRuleCoexistsWithAHunt(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.SetNotifier(&countingSink{})
	ctx := context.Background()
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-xdr4c-breadth-plus-hunt")
	recordTechAlert(t, srv, "dlp", subject, now.Add(-6*time.Minute), "T1552")
	recordTechAlert(t, srv, "nips", subject, now.Add(-2*time.Minute), "T1567.002")
	entity := entityOf(t, srv, subject)

	breadth := controlplane.CrossDomainRule{Window: 10 * time.Minute, MinDomains: 2}
	hunt := controlplane.CrossDomainRule{Name: "credential-staged-then-exfiltrated",
		Window: 10 * time.Minute, MinDomains: 2, TechniqueSequence: []string{"T1552", "T1567.002"}}
	for _, r := range []controlplane.CrossDomainRule{breadth, hunt} {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, r, now); err != nil {
			t.Fatalf("materialize %q: %v", r.Name, err)
		}
	}

	var names []string
	rows, err := pool.Query(ctx,
		`SELECT rule_name FROM incidents WHERE entity_id=$1 AND kind='cross_domain' AND state='open'
		  ORDER BY rule_name`, entity)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if len(names) != 2 || names[0] != "" || names[1] != "credential-staged-then-exfiltrated" {
		t.Fatalf("incidents = %v, want the unnamed breadth incident AND the named hunt — hunts are "+
			"additive, they never replace the rule that catches what nobody anticipated", names)
	}
}

// TestTheScheduledLoopRaisesANarrativeIncidentAndNamesTheHunt is the XDR-4c acceptance test.
//
// It is the SOAR-2 test one level in: SOAR-2 proved the breadth rule runs on a clock without an
// operator request, and this proves the ORDERED-SEQUENCE rule now does too. Before it, Sequence and
// TechniqueSequence were set in exactly one place in the tree outside tests — the GET /incidents query
// parser — so a narrative could be asked about and never reported.
//
// Mutation: pass a nil hunts provider to the loop (the pre-XDR-4c wiring) → the hunt incident never
// appears and the page never names it → this FAILS.
func TestTheScheduledLoopRaisesANarrativeIncidentAndNamesTheHunt(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &countingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()
	now := time.Now().UTC()

	// TWO assets that both satisfy the breadth rule. Only one of them evidences the narrative — so a
	// hunt incident appearing for the other would mean the sequence constraint was not applied at all.
	chained := pseudonym.Of("agent-xdr4c-loop-chained")
	recordTechAlert(t, srv, "dlp", chained, now.Add(-6*time.Minute), "T1552")
	recordTechAlert(t, srv, "nips", chained, now.Add(-2*time.Minute), "T1567.002")
	other := pseudonym.Of("agent-xdr4c-loop-other")
	recordTechAlert(t, srv, "dlp", other, now.Add(-6*time.Minute), "T1027")
	recordTechAlert(t, srv, "hips", other, now.Add(-2*time.Minute), "T1059")

	hunts, err := controlplane.LoadHunts(strings.NewReader(
		`{"hunts":[{"name":"credential-staged-then-exfiltrated",
		            "technique_sequence":["T1552","T1567.002"]}]}`))
	if err != nil {
		t.Fatal(err)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.RunCorrelationLoop(loopCtx,
		func() time.Duration { return 50 * time.Millisecond },
		func() (controlplane.CorrelationRule, controlplane.CrossDomainRule) {
			return controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3},
				controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}
		},
		// Read per tick, exactly as the server reads the hunt file.
		func() []controlplane.CrossDomainRule { return hunts.Rules(30*time.Minute, 2, 0) },
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	chainedEntity := entityOf(t, srv, chained)
	otherEntity := entityOf(t, srv, other)

	// Nobody asked. The narrative incident appears anyway.
	waitFor(t, func() bool {
		var n int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM incidents WHERE entity_id=$1 AND rule_name=$2`,
			chainedEntity, "credential-staged-then-exfiltrated").Scan(&n)
		return n == 1
	})

	// And the page NAMES it — without the name, a narrative incident is indistinguishable from the
	// breadth incident sitting next to it, and naming the narrative is the only thing a sequence rule
	// claims that breadth does not.
	waitFor(t, func() bool {
		for _, n := range sink.notifications() {
			if strings.Contains(n.Detail, "[credential-staged-then-exfiltrated]") {
				return true
			}
		}
		return false
	})

	// The asset that does not evidence the narrative raises the BREADTH incident and no hunt incident.
	var otherHunts, otherBreadth int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE rule_name <> ''), count(*) FILTER (WHERE rule_name = '')
		   FROM incidents WHERE entity_id=$1 AND kind='cross_domain'`, otherEntity).
		Scan(&otherHunts, &otherBreadth); err != nil {
		t.Fatal(err)
	}
	if otherHunts != 0 {
		t.Errorf("an asset that does not evidence the chain raised %d hunt incident(s) — the sequence "+
			"constraint was not applied on the scheduled path", otherHunts)
	}
	if otherBreadth != 1 {
		t.Errorf("breadth incidents for the non-matching asset = %d, want 1 — hunts are additive and "+
			"must never suppress the rule that catches what nobody anticipated", otherBreadth)
	}

	// Page-once still holds for a hunt across many ticks (D220).
	time.Sleep(400 * time.Millisecond)
	var named int
	for _, n := range sink.notifications() {
		if strings.Contains(n.Detail, "[credential-staged-then-exfiltrated]") {
			named++
		}
	}
	if named != 1 {
		t.Errorf("the hunt paged %d times, want 1 — a loop that re-pages every tick is worse than no loop", named)
	}
}

// The rule that raised an incident reaches the LIST, not only the page (XDR-4c).
//
// The list carried neither kind nor rule name, which was survivable while there was one burst rule and
// one cross-domain rule. With hunts configured an asset has several open cross-domain incidents at
// once, and without the rule they are indistinguishable rows differing only in their counts — an
// operator cannot tell which narrative each one is.
//
// Mutation: drop rule_name from the RecentIncidents projection → the hunt's row comes back unnamed →
// this FAILS.
func TestTheIncidentListSaysWhichRuleRaisedEachRow(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.SetNotifier(&countingSink{})
	ctx := context.Background()
	now := time.Now().UTC()

	subject := pseudonym.Of("agent-xdr4c-list")
	recordTechAlert(t, srv, "dlp", subject, now.Add(-6*time.Minute), "T1552")
	recordTechAlert(t, srv, "nips", subject, now.Add(-2*time.Minute), "T1567.002")
	entity := entityOf(t, srv, subject)

	for _, r := range []controlplane.CrossDomainRule{
		{Window: 10 * time.Minute, MinDomains: 2},
		{Name: "credential-staged-then-exfiltrated", Window: 10 * time.Minute, MinDomains: 2,
			TechniqueSequence: []string{"T1552", "T1567.002"}},
	} {
		if _, err := srv.MaterializeCrossDomainIncidents(ctx, r, now); err != nil {
			t.Fatalf("materialize %q: %v", r.Name, err)
		}
	}

	incidents, err := srv.RecentIncidents(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]bool{}
	for _, inc := range incidents {
		if inc.SubjectID != subject {
			continue
		}
		if inc.Kind != "cross_domain" {
			t.Errorf("incident %d for this asset has kind %q, want cross_domain", inc.ID, inc.Kind)
		}
		byRule[inc.RuleName] = true
	}
	if !byRule["credential-staged-then-exfiltrated"] {
		t.Errorf("the listed incidents name rules %v — an operator scanning the list cannot tell "+
			"which narrative raised which row", keysOf(byRule))
	}
	if !byRule[""] {
		t.Errorf("the breadth incident is missing from the list; rules present: %v", keysOf(byRule))
	}
	_ = entity
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
