package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The pipeline is fixed:
//
//	Event → Classification → Policy → Decision → Enforcement → Audit
//
// Stages plug into it. Stages do not know about each other: a Stage receives
// the pipeline State and returns an Outcome, and the Dispatcher owns ordering.
//
// This is deliberately NOT a middleware chain. Middleware composes by each
// layer holding a reference to the next, which is exactly the coupling the
// architecture forbids — a stage that can call next() can wrap, skip or
// reorder its neighbours.
//
// The endpoint pipeline is in-process and synchronous. That is a measured
// decision, not a convenience: the fanotify permission responder answers while
// a real process sits blocked in TASK_UNINTERRUPTIBLE, and T-002 measured that
// budget at 1-3µs typical / 532µs worst case. A broker round trip does not fit.
// NATS is the agent↔control-plane boundary only — see docs/spike-t002-gc-pause.md.

// OutcomeKind is what a stage tells the dispatcher to do next.
type OutcomeKind int

const (
	// OutcomeContinue passes control to the next stage.
	OutcomeContinue OutcomeKind = iota
	// OutcomeDecided terminates the pipeline with a Decision.
	OutcomeDecided
	// OutcomeFailed terminates the pipeline because a stage errored.
	OutcomeFailed
	// OutcomeTimeout terminates the pipeline because a stage exceeded its
	// deadline. Distinct from OutcomeFailed because a timeout is a fail-open
	// bypass and must be countable on its own (D17).
	OutcomeTimeout
)

func (k OutcomeKind) String() string {
	switch k {
	case OutcomeContinue:
		return "continue"
	case OutcomeDecided:
		return "decided"
	case OutcomeFailed:
		return "failed"
	case OutcomeTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// Severity marks how loudly an outcome must be reported. A timeout is
// high-severity by construction: it silently converts a Block into an Allow,
// and an operator who cannot distinguish "nothing sensitive happened" from
// "the classifier timed out" has no signal at all.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarn
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	default:
		return "info"
	}
}

// Outcome is a stage's answer to the dispatcher.
type Outcome struct {
	Kind     OutcomeKind
	Decision *corev1.Decision
	// Stage names the stage that produced a terminal outcome, so a failure is
	// attributable rather than anonymous.
	Stage    string
	Severity Severity
	Err      error
}

// Continue is the ordinary "carry on" outcome.
func Continue() Outcome { return Outcome{Kind: OutcomeContinue} }

// Decided terminates the pipeline with a Decision.
func Decided(d *corev1.Decision) Outcome {
	return Outcome{Kind: OutcomeDecided, Decision: d}
}

// State is the working set carried through the pipeline.
//
// It holds LocalClassification, not ClassificationSummary — classification
// detail is legitimate in-process on the endpoint. The two-type split exists to
// stop it crossing the host boundary, which is the transport's concern.
type State struct {
	Event          *corev1.Event
	Classification *corev1.LocalClassification

	// Context is enrichment Policy consults but does not compute: risk score,
	// asset tier, exception groups, org unit.
	//
	// It is a resolved VALUE, not an accessor. An accessor would let Policy
	// perform an unbounded lookup — a cache miss, a lock, a network call —
	// inside the fanotify permission window that D24 exists to protect.
	// Resolution happens before dispatch, where blocking is acceptable.
	//
	// NIL IN PHASE 1. Nothing computes a Context yet; only the seam exists, so
	// that the policy stage takes the right shape without a later retrofit.
	// See docs/design-t030-context.md.
	Context *Context
}

// Context is a closed, typed set of enrichment facts.
//
// Deliberately not a map[string]string: an open bag would be a surface through
// which a compromised control plane could influence decisions by inventing keys
// a policy happens to read — the threat D14 closed for actions, arriving by a
// different door. Adding a field here should require a deliberate schema change.
//
// The subsystem that computes and distributes Contexts is NOT designed here
// (T-030 designs the seam only). Phase 1 has none.
type Context struct {
	// Version identifies the snapshot. Recorded on the Decision so replay can
	// evaluate against the Context that actually applied (D27).
	Version string
	// ComputedAt lets a policy condition on staleness. Stale is normal and
	// valid — an agent must decide without the network (D1) — but it must be
	// observable rather than hidden.
	ComputedAt time.Time

	// RiskScore in [0,1]. HasRiskScore distinguishes "not computed" from
	// "computed, and this subject looks fine". Conflating them would make every
	// subject look safe whenever analytics is down: a fail-open with no signal.
	RiskScore    float64
	HasRiskScore bool

	AssetTier       AssetTier
	OrgUnit         string
	ExceptionGroups []ExceptionGroup
}

type AssetTier int

const (
	AssetTierUnspecified AssetTier = iota
	AssetTierStandard
	AssetTierSensitive
	AssetTierCrownJewel
)

type ExceptionGroup int

const (
	ExceptionGroupUnspecified ExceptionGroup = iota
	ExceptionGroupPersonalFolder
	ExceptionGroupBreakTime
	ExceptionGroupApprovedTransfer
)

// ErrContextUnavailable is returned when a policy requires an enrichment fact
// that is absent. Policies fail explicitly rather than substituting a default —
// a defaulted risk score reads as "safe" and silently weakens every policy that
// consults it.
var ErrContextUnavailable = errors.New("policy: required context is unavailable")

// ContextVersion returns the version to record on a Decision, or "" when no
// Context applied.
func (s *State) ContextVersion() string {
	if s == nil || s.Context == nil {
		return ""
	}
	return s.Context.Version
}

// Stage is a pipeline stage.
//
// Note what is absent: no registry, no dispatcher handle, no reference to a
// next stage. A stage cannot locate another stage, which is what makes "adding
// a capability never requires editing the core" checkable rather than aspirational.
type Stage interface {
	Name() string
	Run(ctx context.Context, s *State) (Outcome, error)
}

// Registry holds stages in execution order.
type Registry struct {
	stages []Stage
}

// Register appends a stage. Order is registration order — explicit, not
// inferred from priorities or dependencies, both of which would let a stage
// express an opinion about its neighbours.
func (r *Registry) Register(s Stage) {
	r.stages = append(r.stages, s)
}

// Stages returns a copy, so a caller cannot mutate execution order after the
// fact or hand one stage a handle to another.
func (r *Registry) Stages() []Stage {
	out := make([]Stage, len(r.stages))
	copy(out, r.stages)
	return out
}

var (
	ErrReentry     = errors.New("pipeline: re-entry from within a stage is refused")
	ErrStageFailed = errors.New("pipeline: stage failed")
	ErrNoDecision  = errors.New("pipeline: no stage produced a decision")
	// ErrNotRecorded means the pipeline reached a terminal outcome that could
	// not be written to the audit ledger. It is deliberately distinct from
	// ErrStageFailed: the pipeline worked, the record of it did not.
	ErrNotRecorded = errors.New("pipeline: terminal outcome was not recorded")
)

type reentryKey struct{}

// Metrics counts outcomes. Timeouts are counted separately from failures
// because a rising timeout rate is its own signal: it is the cheapest way to
// detect an adversary manufacturing fail-open bypasses (D17).
type Metrics struct {
	Dispatched atomic.Int64
	Decided    atomic.Int64
	Failed     atomic.Int64
	TimedOut   atomic.Int64
}

// Dispatcher runs Events through the registered stages.
type Dispatcher struct {
	registry *Registry
	// StageDeadline bounds every stage invocation. It is owned by the
	// dispatcher, not by stages: a stage that sets its own deadline can set it
	// to infinity, and an unbounded stage is the mechanism by which the
	// responder hangs a machine.
	StageDeadline time.Duration
	Metrics       Metrics
	// Logger receives a structured line for every terminal outcome (T-028). It
	// is nil-safe (a discard logger is used when unset), so embedders and tests
	// are not spammed by default. cmd/* wire a stderr handler.
	Logger *slog.Logger
	// OnOutcome receives every terminal outcome, including timeouts and
	// failures. The dispatcher never drops an Event silently; if this is nil
	// the outcome is still returned to the caller.
	//
	// It returns an error, and the dispatcher surfaces that error to the
	// caller, because this is where the audit append happens. A void callback
	// would make "the Decision was not recorded" structurally unreportable —
	// the caller would have no channel through which to learn it, which is the
	// silent-failure mode the ledger exists to prevent.
	OnOutcome func(ctx context.Context, s *State, o Outcome) error
}

func NewDispatcher(r *Registry, stageDeadline time.Duration) *Dispatcher {
	return &Dispatcher{registry: r, StageDeadline: stageDeadline}
}

// Dispatch runs one Event through the pipeline.
//
// Honest limit: the deadline governs the dispatcher's WAIT, not the stage's
// goroutine. Go cannot preempt an uncooperative function, so a stage that
// ignores its context keeps running after Dispatch returns. That is a leak
// under pathological stages and is why T-011's fail-open watchdog — which
// answers the kernel regardless of what the pipeline is doing — is a separate
// mechanism rather than a consequence of this one.
func (d *Dispatcher) Dispatch(ctx context.Context, e *corev1.Event) (*corev1.Decision, error) {
	if ctx.Value(reentryKey{}) != nil {
		return nil, ErrReentry
	}
	ctx = context.WithValue(ctx, reentryKey{}, true)
	d.Metrics.Dispatched.Add(1)

	st := &State{Event: e}

	for _, stage := range d.registry.Stages() {
		out, err := d.runStage(ctx, stage, st)

		switch out.Kind {
		case OutcomeContinue:
			continue
		case OutcomeDecided:
			d.Metrics.Decided.Add(1)
			// The Decision is returned ALONGSIDE the recording error, not
			// instead of it. The caller is answering a blocked process and
			// must still act; what it must not do is act believing the action
			// was audited. Both facts are true, so both are returned.
			return out.Decision, d.report(ctx, st, out)
		case OutcomeTimeout:
			d.Metrics.TimedOut.Add(1)
			if rerr := d.report(ctx, st, out); rerr != nil {
				return nil, rerr
			}
			return nil, fmt.Errorf("stage %q: %w", stage.Name(), context.DeadlineExceeded)
		case OutcomeFailed:
			d.Metrics.Failed.Add(1)
			if rerr := d.report(ctx, st, out); rerr != nil {
				return nil, rerr
			}
			return nil, fmt.Errorf("%w: %s: %v", ErrStageFailed, stage.Name(), err)
		}
	}

	// Falling off the end is itself a terminal outcome and must be reported —
	// an Event that produced no Decision is not the same as an Event that was
	// allowed, and silence would conflate them.
	out := Outcome{Kind: OutcomeFailed, Stage: "(pipeline)", Severity: SeverityWarn, Err: ErrNoDecision}
	d.Metrics.Failed.Add(1)
	if rerr := d.report(ctx, st, out); rerr != nil {
		return nil, rerr
	}
	return nil, ErrNoDecision
}

func (d *Dispatcher) runStage(ctx context.Context, stage Stage, st *State) (Outcome, error) {
	sctx := ctx
	var cancel context.CancelFunc
	if d.StageDeadline > 0 {
		sctx, cancel = context.WithTimeout(ctx, d.StageDeadline)
		defer cancel()
	}

	type result struct {
		out Outcome
		err error
	}
	// Buffered so an abandoned stage's goroutine can still send and exit
	// rather than blocking forever on a receiver that has gone away.
	done := make(chan result, 1)
	go func() {
		out, err := stage.Run(sctx, st)
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return Outcome{
				Kind: OutcomeFailed, Stage: stage.Name(),
				Severity: SeverityWarn, Err: r.err,
			}, r.err
		}
		r.out.Stage = stage.Name()
		return r.out, nil
	case <-sctx.Done():
		return Outcome{
			Kind: OutcomeTimeout, Stage: stage.Name(),
			// High severity, always. A timeout converts a Block into an Allow;
			// a quiet timeout is indistinguishable from a clean allow.
			Severity: SeverityHigh,
			Err:      sctx.Err(),
		}, sctx.Err()
	}
}

// log returns the configured logger or a discard logger — never nil, so callers
// need no nil check.
func (d *Dispatcher) log() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// slogLevel maps an outcome severity to a slog level, so a level filter surfaces
// the loud events. A timeout is high severity (it turns a Block into an Allow,
// D17) and logs at Warn, greppable by a rising rate.
func slogLevel(s Severity) slog.Level {
	switch s {
	case SeverityHigh:
		return slog.LevelWarn
	case SeverityWarn:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// outcomeCategory is the stable slug for a terminal outcome. It prefers the
// error's identity (so a no-decision fall-off is `no_decision`, a timeout is
// `timeout`) and otherwise maps the kind — a raw stage error is not a sentinel,
// so an OutcomeFailed becomes `stage_failed`.
func outcomeCategory(o Outcome) string {
	if o.Err != nil {
		switch c := Category(o.Err); c {
		case "no_decision", "timeout", "not_recorded", "unreachable", "context_unavailable", "ledger_unavailable", "append_failed":
			return c
		}
	}
	switch o.Kind {
	case OutcomeDecided:
		return "decided"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeFailed:
		return "stage_failed"
	default:
		return o.Kind.String()
	}
}

// report logs the terminal outcome — correlated by event id, categorised, at a
// level matching its severity — and then runs the audit callback. No failure
// path is silent in the logs (D17). Logs carry ids and categories ONLY, never
// content: a log is a wire (D10).
func (d *Dispatcher) report(ctx context.Context, s *State, o Outcome) error {
	eventID := ""
	if s != nil {
		eventID = s.Event.GetEventId()
	}
	d.log().LogAttrs(ctx, slogLevel(o.Severity), "pipeline outcome",
		slog.String("event_id", eventID),
		slog.String("stage", o.Stage),
		slog.String("kind", o.Kind.String()),
		slog.String("severity", o.Severity.String()),
		slog.String("category", outcomeCategory(o)),
	)

	if d.OnOutcome == nil {
		return nil
	}
	if err := d.OnOutcome(ctx, s, o); err != nil {
		e := fmt.Errorf("%w: %v", ErrNotRecorded, err)
		d.log().LogAttrs(ctx, slog.LevelError, "outcome not recorded",
			slog.String("event_id", eventID),
			slog.String("category", Category(e)),
		)
		return e
	}
	return nil
}
