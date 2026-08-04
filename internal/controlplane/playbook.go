package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/retain"
)

// Playbook orchestration (SOAR-4), ADR-12 Tier-1.
//
// An incident is raised and paged (SOAR-1/2) and then nothing happens until an analyst does the same
// first-response sequence by hand: gather what is already known, notify the right people, open a case,
// hold the subject's evidence, tag it. Automating that sequence is the difference between an alert queue
// and an orchestrated response.
//
// TWO PROPERTIES CARRY THE WHOLE DESIGN.
//
// 1. The step vocabulary is CLOSED. A playbook is configuration, and configuration that can name an
//    arbitrary operation is an open action framework by another route — the exact thing D14 refuses for
//    the Action set and the response-intent verbs. A step name outside the registry is refused at LOAD,
//    before anything runs.
//
// 2. NOTHING HERE ACTUATES. No step blocks a flow, kills a process, disables a user or publishes a
//    ResponseIntent. Actuation is Tier-2 (SOAR-7's signed intent seam, gated on four-eyes and a blast
//    radius) and Tier-3 (SOAR-8's runners). A playbook able to actuate would bypass precisely the gates
//    those tickets exist to enforce, so v1 gathers, records and notifies — and the registry's key set is
//    asserted by test so an actuating addition cannot slip in unnoticed.

// StepName is the closed vocabulary of playbook steps. Every name here has exactly one implementation in
// playbookSteps, and playbookSteps contains nothing else — asserted in both directions by test, because
// the compiler cannot enforce map totality.
type StepName string

const (
	// StepEnrich assembles what the platform ALREADY holds about the incident into an annotation. It is
	// local context assembly, NOT threat intel: no external lookup, no IOC store (SOAR-5 owns that, and
	// will replace this body). Named honestly here so "enrich" is not read as more than it does.
	StepEnrich StepName = "enrich"
	// StepNotify pages through the existing fanout, with a dedupe id derived from run+step.
	StepNotify StepName = "notify"
	// StepOpenCase opens an investigation for the incident's subject (which also places a legal hold, in
	// the same transaction, as OpenCaseForIncident always has).
	StepOpenCase StepName = "open-case"
	// StepPlaceHold holds the subject's evidence against purge without opening a case.
	StepPlaceHold StepName = "place-hold"
	// StepTag records a short operator-defined label on the incident.
	StepTag StepName = "tag"
	// StepAnnotate records an operator-supplied note on the incident.
	StepAnnotate StepName = "annotate"
	// StepWaitForApproval parks the run until a human resolves an approval request (SOAR-3).
	StepWaitForApproval StepName = "wait-for-approval"
)

// Run states.
const (
	RunRunning   = "running"
	RunWaiting   = "waiting"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
)

// Step states.
const (
	StepPending = "pending"
	StepRunning = "running"
	StepWaiting = "waiting"
	StepDone    = "done"
	StepFailed  = "failed"
)

var (
	// ErrUnknownStep names a step outside the closed registry. Returned at LOAD.
	ErrUnknownStep = errors.New("controlplane: not a playbook step")
	// ErrBadPlaybook is a structurally invalid playbook (no name, no steps, bad severity, bad argument).
	ErrBadPlaybook = errors.New("controlplane: invalid playbook")
	// errStepWaiting is the sentinel a step returns to PARK the run rather than fail it. Internal: a
	// parked run is not an error condition, it is a state.
	errStepWaiting = errors.New("controlplane: playbook step is waiting")
)

// Step is one entry in a playbook's ordered list.
//
// Arg is an operator-supplied argument for the steps that take one (tag, annotate). It is validated at
// LOAD: a step whose argument shape is unchecked is where a "closed vocabulary" quietly stops being closed.
type Step struct {
	Name StepName `json:"step"`
	Arg  string   `json:"arg,omitempty"`
}

// Trigger selects which incidents a playbook runs on: severity floor, kinds, domains.
//
// An empty Kinds or Domains means "do not constrain on this", never "match nothing" — an operator writing
// only a severity floor gets every kind, which is the reading that matches how the field is written.
type Trigger struct {
	MinSeverity string   `json:"min_severity"`      // low | medium | high | critical
	Kinds       []string `json:"kinds,omitempty"`   // incident kinds (ueba_burst, cross_domain)
	Domains     []string `json:"domains,omitempty"` // at least one of the incident's domains must be listed
}

// Playbook is a trigger plus an ORDERED LIST of steps.
//
// An ordered list, not a DAG, on purpose: a DAG's failure semantics — what happens to sibling branches
// when one fails, whether a join waits or aborts — is a decision that deserves its own round rather than
// being guessed at and baked into a schema.
type Playbook struct {
	Name    string  `json:"name"`
	Trigger Trigger `json:"trigger"`
	Steps   []Step  `json:"steps"`
}

// Identity is how a playbook attributes its own work — never as an operator. A machine's action recorded
// under a human's name is a corrupted audit trail.
// Identity is the automation engine acting as itself, built through the shared principal vocabulary so
// that "is this caller a machine" has one answer (CONSOLE-1). A playbook may REQUEST an approval and
// may never grant one.
func (p Playbook) Identity() string { return PlaybookPrincipal(p.Name) }

// runCtx is what a step implementation gets: which run/step it is, and the incident it acts on.
type runCtx struct {
	pb       Playbook
	runID    int64
	seq      int
	incident StoredIncident
}

// stepFunc implements one step. It returns a short result string recorded on the step row, or an error
// that FAILS the run. errStepWaiting parks the run instead.
type stepFunc func(ctx context.Context, s *Server, rc *runCtx, st Step) (string, error)

// playbookSteps is THE CLOSED REGISTRY. Adding an entry is a deliberate act reviewed against the Tier-1
// boundary; a test asserts this key set equals exactly the declared vocabulary, so neither an
// unimplemented name nor an undeclared implementation can survive.
var playbookSteps = map[StepName]stepFunc{
	StepEnrich:          stepEnrich,
	StepNotify:          stepNotify,
	StepOpenCase:        stepOpenCase,
	StepPlaceHold:       stepPlaceHold,
	StepTag:             stepTag,
	StepAnnotate:        stepAnnotate,
	StepWaitForApproval: stepWaitForApproval,
}

// stepTakesArg records which steps accept an argument, so a step given one it cannot use is refused at
// load rather than silently ignoring it.
var stepTakesArg = map[StepName]bool{StepTag: true, StepAnnotate: true}

var tagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9:_-]{0,63}$`)

const maxAnnotationLen = 512

// LoadPlaybooks parses and VALIDATES operator-supplied playbook configuration (JSON array).
//
// Validation is the security boundary, and it happens here — at load, before a run exists. An unknown step
// name reaching execution would mean the closed registry was decorative.
func LoadPlaybooks(r io.Reader) ([]Playbook, error) {
	var pbs []Playbook
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pbs); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPlaybook, err)
	}
	seen := make(map[string]bool, len(pbs))
	for i := range pbs {
		if err := validatePlaybook(pbs[i]); err != nil {
			return nil, err
		}
		if seen[pbs[i].Name] {
			return nil, fmt.Errorf("%w: duplicate playbook %q", ErrBadPlaybook, pbs[i].Name)
		}
		seen[pbs[i].Name] = true
	}
	return pbs, nil
}

func validatePlaybook(p Playbook) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: a playbook needs a name", ErrBadPlaybook)
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("%w: playbook %q has no steps", ErrBadPlaybook, p.Name)
	}
	if _, ok := severityFloor(p.Trigger.MinSeverity); !ok {
		return fmt.Errorf("%w: playbook %q: %q is not a severity", ErrBadPlaybook, p.Name, p.Trigger.MinSeverity)
	}
	for i, st := range p.Steps {
		// THE CLOSED-REGISTRY CHECK. Removing this line is the mutation the load test targets: an
		// arbitrary step name would then be accepted as configuration.
		if _, ok := playbookSteps[st.Name]; !ok {
			return fmt.Errorf("%w: playbook %q step %d: %q", ErrUnknownStep, p.Name, i, st.Name)
		}
		if err := validateStepArg(p.Name, i, st); err != nil {
			return err
		}
	}
	return nil
}

func validateStepArg(pbName string, i int, st Step) error {
	if st.Arg == "" {
		if st.Name == StepTag || st.Name == StepAnnotate {
			return fmt.Errorf("%w: playbook %q step %d: %q requires an argument", ErrBadPlaybook, pbName, i, st.Name)
		}
		return nil
	}
	if !stepTakesArg[st.Name] {
		return fmt.Errorf("%w: playbook %q step %d: %q takes no argument", ErrBadPlaybook, pbName, i, st.Name)
	}
	switch st.Name {
	case StepTag:
		if !tagPattern.MatchString(st.Arg) {
			return fmt.Errorf("%w: playbook %q step %d: %q is not a valid tag", ErrBadPlaybook, pbName, i, st.Arg)
		}
	case StepAnnotate:
		if len(st.Arg) > maxAnnotationLen {
			return fmt.Errorf("%w: playbook %q step %d: annotation exceeds %d bytes",
				ErrBadPlaybook, pbName, i, maxAnnotationLen)
		}
	}
	return nil
}

// PlaybookFailures counts scheduled playbook ticks that errored — a silent loop is a loop nobody notices
// has stopped orchestrating.
var PlaybookFailures atomic.Int64

// RunPlaybookLoop executes playbooks on an interval.
//
// The caller runs this inside the LEADER's context (ADR-3/PLAT-2b), like RunCorrelationLoop: every replica
// running playbooks would multiply notifications, cases and legal holds. A failing tick is counted and
// logged, never fatal.
//
// BOTH THE INTERVAL AND THE PLAYBOOKS ARE READ PER TICK, and that changed in D292 for a reason worth
// stating: they used to be captured once, at leader startup. So `OPENSHIELD_PLAYBOOKS` was a dynamic
// setting — stored in the database, changeable in the console, reported as applied — that in fact
// required a restart, and an operator enabling orchestration would have watched their saved change do
// nothing. Half the settings applying live and half needing a restart, with nothing distinguishing them,
// is worse than a system where none do.
//
// The loop ALWAYS runs. No playbooks configured means it does no work, rather than not existing — so
// turning orchestration on no longer requires a restart either.
func (s *Server) RunPlaybookLoop(ctx context.Context, interval func() time.Duration,
	playbooks func() []Playbook, log *slog.Logger) {
	retain.DynamicLoop(ctx, interval, func(c context.Context) {
		pbs := playbooks()
		if len(pbs) == 0 {
			return
		}
		if err := s.RunPlaybooksOnce(c, pbs); err != nil {
			PlaybookFailures.Add(1)
			if log != nil {
				log.Error("playbook tick failed", slog.Any("err", err))
			}
		}
	})
}

// RunPlaybooksOnce is one tick: resume unfinished runs, then start runs for newly matching incidents.
//
// Resume comes FIRST so a restart makes progress on existing work before taking on more — an engine that
// starts new runs while old ones stay stuck is how a backlog becomes invisible.
func (s *Server) RunPlaybooksOnce(ctx context.Context, pbs []Playbook) error {
	byName := make(map[string]Playbook, len(pbs))
	for _, p := range pbs {
		byName[p.Name] = p
	}
	if err := s.resumeRuns(ctx, byName); err != nil {
		return err
	}
	for _, p := range pbs {
		if err := s.startRuns(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// resumeRuns continues every run left running or waiting — after a restart, after a leader handover, or
// after a wait-for-approval step parked one.
func (s *Server) resumeRuns(ctx context.Context, byName map[string]Playbook) error {
	rows, err := s.pool.Query(ctx,
		`SELECT id, playbook, incident_id FROM playbook_runs
		  WHERE state IN ('running','waiting') ORDER BY id`)
	if err != nil {
		return err
	}
	type live struct {
		id         int64
		playbook   string
		incidentID int64
	}
	var runs []live
	for rows.Next() {
		var l live
		if err := rows.Scan(&l.id, &l.playbook, &l.incidentID); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, l := range runs {
		pb, ok := byName[l.playbook]
		if !ok {
			// The configuration no longer defines this playbook. Leave the run visibly unfinished rather
			// than discarding operator-visible state or guessing at a step list it never had.
			continue
		}
		inc, err := s.incidentForRun(ctx, l.incidentID)
		if err != nil {
			return err
		}
		if inc == nil {
			continue
		}
		if err := s.executeRun(ctx, pb, l.id, *inc); err != nil {
			return err
		}
	}
	return nil
}

// startRuns creates a run for every incident that matches the playbook's trigger and has none yet.
//
// The NOT EXISTS clause is the mechanism; playbook_runs_once_idx is the backstop that makes two racing
// ticks impossible to both act.
func (s *Server) startRuns(ctx context.Context, pb Playbook) error {
	floor, ok := severityFloor(pb.Trigger.MinSeverity)
	if !ok {
		return fmt.Errorf("%w: %q", ErrBadPlaybook, pb.Trigger.MinSeverity)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen
		   FROM incidents i
		  WHERE i.max_risk >= $1
		    AND i.state <> 'closed'
		    AND ($2::text[] IS NULL OR i.kind = ANY($2))
		    AND ($3::text[] IS NULL OR i.domains && $3)
		    AND NOT EXISTS (SELECT 1 FROM playbook_runs r
		                     WHERE r.playbook = $4 AND r.incident_id = i.id)
		  ORDER BY i.id`,
		floor, nullableTextArray(pb.Trigger.Kinds), nullableTextArray(pb.Trigger.Domains), pb.Name)
	if err != nil {
		return err
	}
	var incidents []StoredIncident
	for rows.Next() {
		var i StoredIncident
		if err := rows.Scan(&i.ID, &i.SubjectID, &i.State, &i.AlertCount, &i.MaxRisk, &i.HostCount,
			&i.FirstSeen, &i.LastSeen); err != nil {
			rows.Close()
			return err
		}
		i.Severity = Severity(i.MaxRisk)
		incidents = append(incidents, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, inc := range incidents {
		runID, created, err := s.createRun(ctx, pb, inc.ID)
		if err != nil {
			return err
		}
		if !created {
			continue // another tick got there first; its executor owns the run
		}
		if err := s.executeRun(ctx, pb, runID, inc); err != nil {
			return err
		}
	}
	return nil
}

// nullableTextArray turns an empty filter into SQL NULL, which the query reads as "do not constrain".
func nullableTextArray(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

// createRun inserts the run and its steps in one transaction: a run whose step list never landed would
// resume as an empty, permanently-running row.
func (s *Server) createRun(ctx context.Context, pb Playbook, incidentID int64) (int64, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx)
	var runID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO playbook_runs (playbook, incident_id, state) VALUES ($1,$2,'running')
		 ON CONFLICT (playbook, incident_id) DO NOTHING RETURNING id`,
		pb.Name, incidentID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil // a run already exists — one per (playbook, incident), by index
	}
	if err != nil {
		return 0, false, err
	}
	for i, st := range pb.Steps {
		if _, err := tx.Exec(ctx,
			`INSERT INTO playbook_steps (run_id, seq, step, arg) VALUES ($1,$2,$3,$4)`,
			runID, i, string(st.Name), st.Arg); err != nil {
			return 0, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return runID, true, nil
}

// executeRun walks the run's steps in order from wherever it left off.
func (s *Server) executeRun(ctx context.Context, pb Playbook, runID int64, inc StoredIncident) error {
	for seq, st := range pb.Steps {
		claimed, err := s.claimStep(ctx, runID, seq)
		if err != nil {
			return err
		}
		if !claimed {
			// Already done (or already failed) — SKIP. This is the whole idempotency property: a
			// resumed run must not repeat a step whose effect already landed.
			continue
		}
		impl, ok := playbookSteps[st.Name]
		if !ok {
			// Unreachable for a loaded playbook (the registry check ran at load), but a step that
			// cannot execute must fail loudly rather than be skipped as if it had succeeded.
			return s.failRun(ctx, runID, seq, fmt.Errorf("%w: %q", ErrUnknownStep, st.Name))
		}
		rc := &runCtx{pb: pb, runID: runID, seq: seq, incident: inc}
		result, err := impl(ctx, s, rc, st)
		switch {
		case errors.Is(err, errStepWaiting):
			return s.parkRun(ctx, runID, seq, result)
		case err != nil:
			return s.failRun(ctx, runID, seq, err)
		}
		if err := s.completeStep(ctx, runID, seq, result); err != nil {
			return err
		}
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET state='succeeded', finished_at=now()
		  WHERE id=$1 AND state IN ('running','waiting')`, runID)
	return err
}

// claimStep marks a step running and reports whether THIS executor may run it.
//
// The `state <> 'done'` predicate is the already-completed guard, and it lives HERE — in the database,
// atomic with the claim — rather than in a Go conditional, because a crash erases in-memory state and a
// leader handover can briefly overlap two executors. Removing it re-runs completed steps; the resumption
// test's mutation is exactly that.
func (s *Server) claimStep(ctx context.Context, runID int64, seq int) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE playbook_steps SET state='running', started_at = coalesce(started_at, now())
		  WHERE run_id=$1 AND seq=$2 AND state <> 'done'`, runID, seq)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Server) completeStep(ctx context.Context, runID int64, seq int, result string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_steps SET state='done', result=$3, finished_at=now() WHERE run_id=$1 AND seq=$2`,
		runID, seq, truncate(result, 512))
	return err
}

// parkRun records a run waiting on a human. The step stays claimable (state 'waiting', not 'done'), so the
// next tick re-enters it and re-reads the approval.
func (s *Server) parkRun(ctx context.Context, runID int64, seq int, result string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE playbook_steps SET state='waiting', result=$3 WHERE run_id=$1 AND seq=$2`,
		runID, seq, truncate(result, 512)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE playbook_runs SET state='waiting' WHERE id=$1`, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// failRun records the failing step and the run's failure. No later step executes: v1 has no retries and no
// backoff — an operator inspects the failure. A half-executed sequence that silently continued would
// produce a case whose enrichment never happened, which is worse than a visible failure.
func (s *Server) failRun(ctx context.Context, runID int64, seq int, cause error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE playbook_steps SET state='failed', error=$3, finished_at=now() WHERE run_id=$1 AND seq=$2`,
		runID, seq, truncate(cause.Error(), 512)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE playbook_runs SET state='failed', error=$2, finished_at=now() WHERE id=$1`,
		runID, truncate(cause.Error(), 512)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// incidentForRun reloads the incident a run acts on. A run whose incident vanished (a purge) is skipped
// rather than executed against a zero value.
func (s *Server) incidentForRun(ctx context.Context, id int64) (*StoredIncident, error) {
	var i StoredIncident
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen
		   FROM incidents WHERE id=$1`, id).
		Scan(&i.ID, &i.SubjectID, &i.State, &i.AlertCount, &i.MaxRisk, &i.HostCount, &i.FirstSeen, &i.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	i.Severity = Severity(i.MaxRisk)
	return &i, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// PlaybookRun is a run as an operator reads it.
type PlaybookRun struct {
	ID         int64          `json:"id"`
	Playbook   string         `json:"playbook"`
	IncidentID int64          `json:"incident_id"`
	State      string         `json:"state"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Steps      []PlaybookStep `json:"steps"`
}

// PlaybookStep is one recorded step transition: state, outcome and timing — the raw material SOAR-6's
// analyst metrics derive from.
type PlaybookStep struct {
	Seq        int        `json:"seq"`
	Step       string     `json:"step"`
	State      string     `json:"state"`
	Result     string     `json:"result,omitempty"`
	ApprovalID *int64     `json:"approval_id,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// PlaybookRunFor returns a run with its steps, for a given playbook and incident.
func (s *Server) PlaybookRunFor(ctx context.Context, playbook string, incidentID int64) (*PlaybookRun, error) {
	var r PlaybookRun
	err := s.pool.QueryRow(ctx,
		`SELECT id, playbook, incident_id, state, started_at, finished_at, error
		   FROM playbook_runs WHERE playbook=$1 AND incident_id=$2`, playbook, incidentID).
		Scan(&r.ID, &r.Playbook, &r.IncidentID, &r.State, &r.StartedAt, &r.FinishedAt, &r.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT seq, step, state, result, approval_id, started_at, finished_at, error
		   FROM playbook_steps WHERE run_id=$1 ORDER BY seq`, r.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var st PlaybookStep
		if err := rows.Scan(&st.Seq, &st.Step, &st.State, &st.Result, &st.ApprovalID,
			&st.StartedAt, &st.FinishedAt, &st.Error); err != nil {
			return nil, err
		}
		r.Steps = append(r.Steps, st)
	}
	return &r, rows.Err()
}
