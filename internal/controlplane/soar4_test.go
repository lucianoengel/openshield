package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SOAR-4: the playbook engine.
//
// Two properties carry the ticket and both are asserted with a mutation:
//   - the step registry is CLOSED and enforced at LOAD (an unknown step never reaches execution);
//   - a resumed run NEVER re-executes a completed step (the acceptance criterion, "killing the server
//     mid-run resumes without duplicating a step").
//
// A note on what these tests assert on, because it has bitten before (D242): the notify step's dedupe id
// is derived from run+step, so SIEM-12's durable dedupe would SUPPRESS a duplicate page and make the
// duplication mutation pass. Every duplication assertion here therefore counts `incident_annotations`,
// which nothing dedupes.

func seedIncident(t *testing.T, pool *pgxpool.Pool, kind, subject string, risk float64, domains []string) int64 {
	t.Helper()
	now := time.Now().UTC()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count,
		                        first_seen, last_seen, domains)
		 VALUES ($1,$2,'open',4,$3,2,$4,$5,$6) RETURNING id`,
		kind, subject, risk, now.Add(-10*time.Minute), now, domains).Scan(&id); err != nil {
		t.Fatalf("seeding incident: %v", err)
	}
	return id
}

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", sql, err)
	}
	return n
}

func firstResponse() controlplane.Playbook {
	return controlplane.Playbook{
		Name:    "first-response",
		Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityHigh},
		Steps: []controlplane.Step{
			{Name: controlplane.StepEnrich},
			{Name: controlplane.StepNotify},
			{Name: controlplane.StepOpenCase},
		},
	}
}

// TestPlaybookRunsFirstResponseOnHighSeverityIncident is the acceptance case: a high-severity incident
// auto-runs enrich→notify→open-case, in order, with every effect observable — and repeated ticks do not
// run it again.
func TestPlaybookRunsFirstResponseOnHighSeverityIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &countingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()

	pb := firstResponse()
	incID := seedIncident(t, pool, "cross_domain", "subject-soar4-accept", 0.88, []string{"dlp", "hips"})

	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("playbook tick: %v", err)
	}

	run, err := srv.PlaybookRunFor(ctx, pb.Name, incID)
	if err != nil {
		t.Fatal(err)
	}
	if run == nil {
		t.Fatal("a high-severity incident started no playbook run — the engine is inert")
	}
	if run.State != controlplane.RunSucceeded {
		t.Fatalf("run state = %q, want %q (error %q)", run.State, controlplane.RunSucceeded, run.Error)
	}
	// Order is declared order, and every step carries its outcome and timing (SOAR-6's raw material).
	wantSteps := []string{"enrich", "notify", "open-case"}
	for i, w := range wantSteps {
		if i >= len(run.Steps) {
			t.Fatalf("run recorded %d steps, want %d", len(run.Steps), len(wantSteps))
		}
		st := run.Steps[i]
		if st.Step != w || st.Seq != i {
			t.Errorf("step %d = %q(seq %d), want %q(seq %d)", i, st.Step, st.Seq, w, i)
		}
		if st.State != controlplane.StepDone {
			t.Errorf("step %q state = %q, want done (error %q)", st.Step, st.State, st.Error)
		}
		if st.StartedAt == nil || st.FinishedAt == nil {
			t.Errorf("step %q has no start/finish timing recorded", st.Step)
		}
	}

	// Each step's EFFECT, not just its bookkeeping.
	annotations, err := srv.IncidentAnnotations(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	if len(annotations) != 1 || annotations[0].Kind != "enrichment" {
		t.Fatalf("enrich produced %d annotation(s) %v, want exactly one enrichment", len(annotations), annotations)
	}
	if annotations[0].Author != "playbook:first-response" {
		t.Errorf("annotation author = %q, want the playbook identity — a machine's work must never be "+
			"attributed to a human", annotations[0].Author)
	}
	waitFor(t, func() bool { return sink.count() >= 1 })
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, "subject-soar4-accept"); n != 1 {
		t.Errorf("open-case produced %d case(s), want 1", n)
	}
	// open-case also holds the subject's evidence, in the same transaction (HON-2).
	held, err := srv.IsUnderLegalHold(ctx, "subject-soar4-accept")
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Error("open-case left the subject's evidence purgeable")
	}

	// Repeated ticks: one run, one set of effects. A playbook that re-runs every tick is worse than none.
	for i := 0; i < 5; i++ {
		if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
			t.Fatalf("repeat tick %d: %v", i, err)
		}
	}
	if n := countRows(t, pool, `SELECT count(*) FROM playbook_runs WHERE incident_id=$1`, incID); n != 1 {
		t.Errorf("after 5 further ticks there are %d runs, want 1", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE incident_id=$1`, incID); n != 1 {
		t.Errorf("after 5 further ticks there are %d annotations, want 1", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, "subject-soar4-accept"); n != 1 {
		t.Errorf("after 5 further ticks there are %d cases, want 1", n)
	}
}

// TestPlaybookTriggerDoesNotFireOnNonMatchingIncidents pins the trigger: below the severity floor, or a
// kind/domain the playbook did not ask for, starts NOTHING.
func TestPlaybookTriggerDoesNotFireOnNonMatchingIncidents(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	pb := controlplane.Playbook{
		Name: "cross-domain-only",
		Trigger: controlplane.Trigger{
			MinSeverity: controlplane.SeverityHigh,
			Kinds:       []string{"cross_domain"},
			Domains:     []string{"dlp"},
		},
		Steps: []controlplane.Step{{Name: controlplane.StepTag, Arg: "auto-triage"}},
	}

	lowSev := seedIncident(t, pool, "cross_domain", "subject-lowsev", 0.40, []string{"dlp"})
	wrongKind := seedIncident(t, pool, "ueba_burst", "subject-wrongkind", 0.95, []string{"dlp"})
	wrongDomain := seedIncident(t, pool, "cross_domain", "subject-wrongdomain", 0.95, []string{"nips"})
	matching := seedIncident(t, pool, "cross_domain", "subject-matching", 0.95, []string{"dlp", "nips"})

	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("playbook tick: %v", err)
	}
	for _, tc := range []struct {
		name string
		id   int64
	}{{"below the severity floor", lowSev}, {"a kind the trigger excludes", wrongKind},
		{"a domain the trigger excludes", wrongDomain}} {
		run, err := srv.PlaybookRunFor(ctx, pb.Name, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if run != nil {
			t.Errorf("an incident with %s started a run — the trigger is not selecting", tc.name)
		}
	}
	run, err := srv.PlaybookRunFor(ctx, pb.Name, matching)
	if err != nil {
		t.Fatal(err)
	}
	if run == nil || run.State != controlplane.RunSucceeded {
		t.Fatalf("the matching incident did not run to completion: %+v", run)
	}
	if n := countRows(t, pool,
		`SELECT count(*) FROM incident_annotations WHERE incident_id=$1 AND kind='tag' AND body='auto-triage'`,
		matching); n != 1 {
		t.Errorf("the tag step produced %d tag(s), want 1", n)
	}
}

// TestKilledMidRunResumesWithoutDuplicatingAStep is the ticket's literal acceptance criterion.
//
// It reproduces the state a control plane killed mid-run leaves behind — the run still `running`, the
// completed step `done`, the rest `pending` — and then resumes with a FRESH Server, as a restart would.
//
// MUTATION (verified to FAIL): remove `AND state <> 'done'` from claimStep's predicate → the completed
// enrich step runs a second time → two enrichment annotations → this test fails.
func TestKilledMidRunResumesWithoutDuplicatingAStep(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	pb := firstResponse()
	subject := "subject-soar4-resume"
	incID := seedIncident(t, pool, "cross_domain", subject, 0.91, []string{"dlp"})

	// --- before the kill: the engine runs, and we stop it after the first step. ---
	first := controlplane.New(pool)
	firstSink := &countingSink{}
	first.SetNotifier(firstSink)
	truncated := pb
	truncated.Steps = pb.Steps[:1] // the engine only ever saw step 0 before the process died
	if err := first.RunPlaybooksOnce(ctx, []controlplane.Playbook{truncated}); err != nil {
		t.Fatalf("pre-kill tick: %v", err)
	}
	// Reconstruct the on-disk state a kill leaves: the run is unfinished and the later steps exist as
	// pending rows (createRun writes the full step list in one transaction, so a real kill after step 0
	// leaves exactly this).
	if _, err := pool.Exec(ctx,
		`UPDATE playbook_runs SET state='running', finished_at=NULL WHERE incident_id=$1`, incID); err != nil {
		t.Fatal(err)
	}
	var runID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM playbook_runs WHERE incident_id=$1`, incID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	for seq := 1; seq < len(pb.Steps); seq++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO playbook_steps (run_id, seq, step) VALUES ($1,$2,$3)`,
			runID, seq, string(pb.Steps[seq].Name)); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE incident_id=$1`, incID); n != 1 {
		t.Fatalf("before the restart there are %d enrichment annotations, want 1 — the setup is wrong", n)
	}

	// --- the restart: a FRESH Server picks the run up. ---
	second := controlplane.New(pool)
	secondSink := &countingSink{}
	second.SetNotifier(secondSink)
	if err := second.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("post-restart tick: %v", err)
	}

	run, err := second.PlaybookRunFor(ctx, pb.Name, incID)
	if err != nil {
		t.Fatal(err)
	}
	if run == nil || run.State != controlplane.RunSucceeded {
		t.Fatalf("the resumed run did not complete: %+v", run)
	}
	// It CONTINUED: the later steps ran.
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, subject); n != 1 {
		t.Errorf("open-case produced %d case(s) after resume, want 1 — the run did not continue", n)
	}
	// And it did NOT repeat: the completed step's effect happened exactly once.
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE incident_id=$1`, incID); n != 1 {
		t.Errorf("the already-completed enrich step left %d annotations after a restart, want exactly 1 — "+
			"a resumed run that repeats work is how operators stop trusting automation", n)
	}
}

// TestWaitForApprovalParksTheRunUntilAHumanDecides covers SOAR-4's use of SOAR-3 — the approvals object's
// first automation consumer (its only caller until now was case closure).
//
// It also exercises resumption for real: the parked run is resumed by a FRESH Server, and the already
// completed enrich step must not repeat.
func TestWaitForApprovalParksTheRunUntilAHumanDecides(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	pb := controlplane.Playbook{
		Name:    "gated-response",
		Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityHigh},
		Steps: []controlplane.Step{
			{Name: controlplane.StepEnrich},
			{Name: controlplane.StepWaitForApproval},
			{Name: controlplane.StepOpenCase},
		},
	}
	subject := "subject-soar4-approval"
	incID := seedIncident(t, pool, "cross_domain", subject, 0.93, []string{"dlp"})

	srv := controlplane.New(pool)
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	run, err := srv.PlaybookRunFor(ctx, pb.Name, incID)
	if err != nil {
		t.Fatal(err)
	}
	if run == nil || run.State != controlplane.RunWaiting {
		t.Fatalf("the run did not park on wait-for-approval: %+v", run)
	}
	if run.Steps[2].State != controlplane.StepPending {
		t.Errorf("the step AFTER the gate is %q — a parked run must not proceed on its own", run.Steps[2].State)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, subject); n != 0 {
		t.Fatalf("open-case ran while the gate was pending (%d cases)", n)
	}
	if run.Steps[1].ApprovalID == nil {
		t.Fatal("the gate step recorded no approval id")
	}
	approvalID := *run.Steps[1].ApprovalID

	// The requester is the PLAYBOOK, not an operator: a machine's request must never be attributed to a
	// human. That is also why this is a one-operator human gate, not two-human four-eyes.
	a, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectPlaybookStep,
		fmt.Sprintf("%d:%d", run.ID, run.Steps[1].Seq))
	if err != nil {
		t.Fatal(err)
	}
	if a.Requester != "playbook:gated-response" {
		t.Errorf("approval requester = %q, want the playbook identity", a.Requester)
	}

	// Ticking again while it is still pending changes nothing — and, crucially, does not re-run enrich.
	restarted := controlplane.New(pool)
	if err := restarted.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("tick while pending: %v", err)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE incident_id=$1`, incID); n != 1 {
		t.Errorf("a parked run re-ran its completed enrich step (%d annotations, want 1)", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM approvals WHERE subject_kind='playbook-step'`); n != 1 {
		t.Errorf("resuming opened %d approval requests, want 1 — a second live request would let the "+
			"requester shop for an approver", n)
	}

	// A human approves; the run finishes.
	if err := restarted.ResolveApproval(ctx, approvalID, "cert:alice", true); err != nil {
		t.Fatalf("approving: %v", err)
	}
	if err := restarted.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("tick after approval: %v", err)
	}
	run, err = restarted.PlaybookRunFor(ctx, pb.Name, incID)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != controlplane.RunSucceeded {
		t.Fatalf("the approved run did not complete: state=%q err=%q", run.State, run.Error)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, subject); n != 1 {
		t.Errorf("after approval the run produced %d case(s), want 1", n)
	}
	if !strings.Contains(run.Steps[1].Result, "cert:alice") {
		t.Errorf("the gate step recorded %q — the approving operator must be on the record", run.Steps[1].Result)
	}
}

// TestDeniedOrExpiredApprovalFailsTheRun: a refused gate stops the run. Proceeding past it would make the
// gate decorative — and what a refusal MEANS is the requesting feature's decision, which for a playbook is
// "stop".
func TestDeniedOrExpiredApprovalFailsTheRun(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	gated := func(name string) controlplane.Playbook {
		return controlplane.Playbook{
			Name:    name,
			Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityHigh},
			Steps: []controlplane.Step{
				{Name: controlplane.StepWaitForApproval},
				{Name: controlplane.StepOpenCase},
			},
		}
	}
	srv := controlplane.New(pool)

	// --- denial ---
	denyPB := gated("deny-path")
	denyInc := seedIncident(t, pool, "cross_domain", "subject-soar4-deny", 0.92, nil)
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{denyPB}); err != nil {
		t.Fatal(err)
	}
	run, err := srv.PlaybookRunFor(ctx, denyPB.Name, denyInc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, *run.Steps[0].ApprovalID, "cert:bob", false); err != nil {
		t.Fatalf("denying: %v", err)
	}
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{denyPB}); err != nil {
		t.Fatal(err)
	}
	run, err = srv.PlaybookRunFor(ctx, denyPB.Name, denyInc)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != controlplane.RunFailed {
		t.Errorf("a DENIED gate left the run %q, want failed", run.State)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, "subject-soar4-deny"); n != 0 {
		t.Errorf("the run proceeded past a denied gate (%d cases opened)", n)
	}

	// --- expiry: the TTL elapses with nobody deciding. A week-old request is not consent. ---
	expPB := gated("expiry-path")
	expInc := seedIncident(t, pool, "cross_domain", "subject-soar4-expire", 0.92, nil)
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{expPB}); err != nil {
		t.Fatal(err)
	}
	run, err = srv.PlaybookRunFor(ctx, expPB.Name, expInc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id=$1`,
		*run.Steps[0].ApprovalID); err != nil {
		t.Fatal(err)
	}
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{expPB}); err != nil {
		t.Fatal(err)
	}
	run, err = srv.PlaybookRunFor(ctx, expPB.Name, expInc)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != controlplane.RunFailed {
		t.Errorf("an EXPIRED gate left the run %q, want failed", run.State)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM cases WHERE subject_id=$1`, "subject-soar4-expire"); n != 0 {
		t.Errorf("the run proceeded past an expired gate (%d cases opened)", n)
	}
}

// TestFailingStepFailsTheRunAndStopsIt: no retries, no partial continuation. A sequence that silently
// continued would produce a case whose enrichment never happened.
func TestFailingStepFailsTheRunAndStopsIt(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	// An incident with an EMPTY subject makes open-case fail (OpenCaseForIncident requires a subject),
	// without needing a fault-injection seam that would itself be untested code.
	incID := seedIncident(t, pool, "cross_domain", "", 0.95, []string{"dlp"})
	pb := controlplane.Playbook{
		Name:    "will-fail",
		Trigger: controlplane.Trigger{MinSeverity: controlplane.SeverityHigh},
		Steps: []controlplane.Step{
			{Name: controlplane.StepOpenCase},
			{Name: controlplane.StepTag, Arg: "never-reached"},
		},
	}
	srv := controlplane.New(pool)
	if err := srv.RunPlaybooksOnce(ctx, []controlplane.Playbook{pb}); err != nil {
		t.Fatalf("tick: %v", err)
	}
	run, err := srv.PlaybookRunFor(ctx, pb.Name, incID)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != controlplane.RunFailed {
		t.Fatalf("run state = %q, want failed", run.State)
	}
	if run.Steps[0].State != controlplane.StepFailed || run.Steps[0].Error == "" {
		t.Errorf("the failing step recorded state=%q error=%q — a failure with no reason is not actionable",
			run.Steps[0].State, run.Steps[0].Error)
	}
	if run.Steps[1].State != controlplane.StepPending {
		t.Errorf("the step after a failure is %q, want pending — a failed run must not continue",
			run.Steps[1].State)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM incident_annotations WHERE incident_id=$1`, incID); n != 0 {
		t.Errorf("a step after the failure produced %d annotation(s)", n)
	}
}

// TestUnknownStepIsRefusedAtLoad — the closed registry, enforced BEFORE anything runs.
//
// MUTATION (verified to FAIL): drop the `playbookSteps` membership check in validatePlaybook → an
// arbitrary step name loads as configuration → this test fails.
func TestUnknownStepIsRefusedAtLoad(t *testing.T) {
	cfg := `[{"name":"hostile","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"},{"step":"exfiltrate"}]}]`
	pbs, err := controlplane.LoadPlaybooks(strings.NewReader(cfg))
	if err == nil {
		t.Fatalf("a playbook naming an unregistered step LOADED (%+v) — the closed registry is decorative", pbs)
	}
	if !errors.Is(err, controlplane.ErrUnknownStep) {
		t.Errorf("error = %v, want ErrUnknownStep", err)
	}
	if !strings.Contains(err.Error(), "exfiltrate") {
		t.Errorf("the error does not name the offending step: %v", err)
	}
	if pbs != nil {
		t.Error("a refused configuration returned playbooks — a partial load makes the check meaningless")
	}

	// The valid shape still loads, with order preserved.
	ok := `[{"name":"fine","trigger":{"min_severity":"high","kinds":["cross_domain"]},
	         "steps":[{"step":"enrich"},{"step":"tag","arg":"auto"},{"step":"open-case"}]}]`
	loaded, err := controlplane.LoadPlaybooks(strings.NewReader(ok))
	if err != nil {
		t.Fatalf("a valid playbook was refused: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Steps) != 3 ||
		loaded[0].Steps[0].Name != controlplane.StepEnrich ||
		loaded[0].Steps[2].Name != controlplane.StepOpenCase {
		t.Fatalf("declared order was not preserved: %+v", loaded)
	}
}

// TestPlaybookConfigValidation covers the rest of what load refuses: a bad severity, no steps, an
// argument on a step that takes none, and a malformed tag. A step whose argument shape is unchecked is
// where a "closed vocabulary" quietly stops being closed.
func TestPlaybookConfigValidation(t *testing.T) {
	for _, tc := range []struct{ name, cfg string }{
		{"unknown severity", `[{"name":"a","trigger":{"min_severity":"urgent"},"steps":[{"step":"enrich"}]}]`},
		{"no steps", `[{"name":"a","trigger":{"min_severity":"low"},"steps":[]}]`},
		{"no name", `[{"name":"","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"}]}]`},
		{"argument on a step that takes none",
			`[{"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"enrich","arg":"x"}]}]`},
		{"tag with no argument", `[{"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"tag"}]}]`},
		{"tag with a hostile charset",
			`[{"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"tag","arg":"a b; DROP"}]}]`},
		{"duplicate playbook names",
			`[{"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"}]},
			  {"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"}]}]`},
		{"unknown field", `[{"name":"a","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"}],"exec":"sh"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := controlplane.LoadPlaybooks(strings.NewReader(tc.cfg)); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

// TestStepRegistryIsClosedAndNonActuating pins ADR-12 Tier-1 in two directions.
//
// The declared vocabulary and the registry must be IDENTICAL (the compiler cannot enforce map totality),
// and the registry must contain exactly the seven Tier-1 names — so adding an actuating step cannot land
// without changing an assertion that says, in words, why it must not.
func TestStepRegistryIsClosedAndNonActuating(t *testing.T) {
	want := []string{"annotate", "enrich", "notify", "open-case", "place-hold", "tag", "wait-for-approval"}
	if got := controlplane.PlaybookStepRegistry(); !reflect.DeepEqual(got, want) {
		t.Errorf("step registry = %v, want exactly %v.\nEvery one of these GATHERS, RECORDS or NOTIFIES. "+
			"Actuation belongs to SOAR-7's signed intent seam (four-eyes + blast radius) and SOAR-8's "+
			"runners; a playbook that could actuate would route around both.", got, want)
	}
	if got, decl := controlplane.PlaybookStepRegistry(), controlplane.DeclaredPlaybookSteps(); !reflect.DeepEqual(got, decl) {
		t.Errorf("the registry %v and the declared vocabulary %v differ — a declared name with no "+
			"implementation, or an implementation with no declared name, is a failure", got, decl)
	}

	// And the engine does not reach the actuation seam at all.
	for _, f := range []string{"playbook.go", "playbook_steps.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"PublishIntents", "ResponseIntent", "SetRiskSigner", "PublishRisk"} {
			if strings.Contains(string(src), banned+"(") {
				t.Errorf("%s calls %s — v1 is ADR-12 Tier-1 and must not actuate", f, banned)
			}
		}
	}
}

// TestPlaybookLoopStopsWithLeadershipAndSurvivesAFailingTick: the loop runs inside the LEADER's context
// (every replica running playbooks would multiply notifications, cases and holds), and one bad tick must
// not end orchestration for the process lifetime.
func TestPlaybookLoopStopsWithLeadershipAndSurvivesAFailingTick(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	srv := controlplane.New(pool)
	pb := firstResponse()
	incID := seedIncident(t, pool, "cross_domain", "subject-soar4-loop", 0.96, []string{"dlp"})

	// A tick that fails: an unusable trigger. The counter moves and the loop keeps running.
	before := controlplane.PlaybookFailures.Load()
	bad := pb
	bad.Name = "bad-trigger"
	bad.Trigger.MinSeverity = "not-a-severity"
	loopCtx, cancel := context.WithCancel(ctx)
	go srv.RunPlaybookLoop(loopCtx, func() time.Duration { return 20 * time.Millisecond },
		func() []controlplane.Playbook { return []controlplane.Playbook{bad} }, nil)
	waitFor(t, func() bool { return controlplane.PlaybookFailures.Load() > before })
	failed := controlplane.PlaybookFailures.Load()
	waitFor(t, func() bool { return controlplane.PlaybookFailures.Load() > failed })
	cancel()

	// Losing leadership stops execution: a good playbook under a cancelled context runs nothing.
	dead, deadCancel := context.WithCancel(ctx)
	deadCancel()
	go srv.RunPlaybookLoop(dead, func() time.Duration { return 20 * time.Millisecond },
		func() []controlplane.Playbook { return []controlplane.Playbook{pb} }, nil)
	time.Sleep(200 * time.Millisecond)
	if n := countRows(t, pool, `SELECT count(*) FROM playbook_runs WHERE incident_id=$1`, incID); n != 0 {
		t.Errorf("a demoted instance started %d run(s) — playbook execution must be leader-only", n)
	}

	// And under a live context the same playbook does run, so the assertion above is not vacuous.
	liveCtx, liveCancel := context.WithCancel(ctx)
	defer liveCancel()
	go srv.RunPlaybookLoop(liveCtx, func() time.Duration { return 20 * time.Millisecond },
		func() []controlplane.Playbook { return []controlplane.Playbook{pb} }, nil)
	waitFor(t, func() bool {
		return countRows(t, pool, `SELECT count(*) FROM playbook_runs WHERE incident_id=$1`, incID) == 1
	})
}
