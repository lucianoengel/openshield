// Package engine assembles the endpoint pipeline — the walking skeleton.
//
// It runs classify → policy → decide → audit as one flow. It is the THIRD
// endpoint component, distinct from the privileged fanotify agent and the
// sandboxed parser worker, because it must hold what neither of them can:
//
//   - OPA (policy) uses encoding/json, which check-agent-deps BANS from the
//     privileged agent (D29) — so policy cannot run there.
//   - the audit ledger needs Postgres (network), which the worker's seccomp
//     filter DENIES (D35) — so audit cannot run there.
//
// The engine is unprivileged and network-capable; it calls the worker for
// classification (content stays in the worker, D29) and writes the local
// forward-secure ledger (D30). The three-process shape is a consequence of the
// constraints, not a choice.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// classifier is the subset of the worker the engine needs — an interface so the
// classify stage is testable without spawning a process.
type classifier interface {
	Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)
}

// classifyStage hands a file to the unprivileged worker and puts the result on
// the pipeline State. It receives detector hits — type + confidence + count —
// NEVER matched content: LocalClassification's matched text stays in the worker
// (D29), so the classification this builds carries empty matched_text.
type classifyStage struct{ w classifier }

func (classifyStage) Name() string { return "classify" }

func (c classifyStage) Run(ctx context.Context, s *core.State) (core.Outcome, error) {
	fs := s.Event.GetFilesystem()
	if fs == nil {
		// A non-file event (a DNS query, an HTTP request, a process exec, a USB insert)
		// carries no file CONTENT to classify — the policy decides on its metadata (the
		// queried name, the exec path) via buildInput. Hand the policy an EMPTY
		// classification and continue; the content worker is not called. This is NOT a
		// skipped scan masquerading as "found nothing": there is genuinely no content for
		// this event kind, and a file event that reaches classify must still have a path.
		s.Classification = &corev1.LocalClassification{EventId: s.Event.GetEventId()}
		return core.Continue(), nil
	}
	path := fs.GetResolvedPath()
	if path == "" {
		return core.Outcome{}, fmt.Errorf("classify: file event carries no resolvable path")
	}
	resp, err := c.w.Classify(ctx, &corev1.ClassifyRequest{
		RequestId: s.Event.GetEventId(), EventId: s.Event.GetEventId(),
		Subject: &corev1.ClassifyRequest_Path{Path: path},
	})
	if err != nil {
		// A worker failure is NOT "nothing found" — surface it so a failed parse
		// is auditable, never a silent clean result (D17).
		return core.Outcome{}, fmt.Errorf("classify: worker: %w", err)
	}
	if resp.GetError() != "" {
		return core.Outcome{}, fmt.Errorf("classify: worker reported: %s", resp.GetError())
	}

	// Build a content-free LocalClassification: one match per hit occurrence,
	// carrying detector type and confidence but EMPTY matched_text. The policy
	// aggregates by type into type+confidence+count, which is all it reads.
	lc := &corev1.LocalClassification{EventId: s.Event.GetEventId()}
	for _, h := range resp.GetHits() {
		for i := uint32(0); i < h.GetCount(); i++ {
			lc.Matches = append(lc.Matches, &corev1.LocalMatch{
				DetectorType: h.GetDetectorType(),
				Confidence:   h.GetConfidence(),
				// MatchedText deliberately empty — no content crossed the IPC.
			})
		}
	}
	s.Classification = lc
	return core.Continue(), nil
}

// Engine runs the assembled pipeline for one event.
type Engine struct {
	disp   *core.Dispatcher
	ledger core.Ledger
	now    func() time.Time
	logger *slog.Logger

	// telemetry projects real detections to the control plane. nil = no projection
	// (the default); the local ledger is the system of record (D30). Set via
	// SetTelemetry (D80).
	telemetry Projector

	// Enforcers carry out Decisions post-decision (Phase 2). EMPTY by default —
	// with no enforcers the engine is observe-only (D1): it decides and records,
	// and enforces nothing. Registering an enforcer turns enforcement on, per
	// action. Enforcement is CONTAINMENT after detection, not prevention (D16).
	Enforcers []core.Enforcer
}

// New assembles the pipeline: classify (via the worker) → policy → decide, with
// the audit sink recording every terminal outcome and the logger correlating it.
func New(w classifier, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	var reg core.Registry
	reg.Register(classifyStage{w: w})
	reg.Register(policy)
	disp := core.NewDispatcher(&reg, stageDeadline)
	disp.OnOutcome = core.NewAuditSink(ledger).Record
	disp.Logger = logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{disp: disp, ledger: ledger, now: time.Now, logger: logger}
}

// Process runs one event through the pipeline, records the Decision, then — if an
// enforcer can carry out its action — enforces it POST-DECISION. The order is
// deliberate: the Decision is recorded (by the dispatcher's audit sink) BEFORE
// enforcement is attempted, so the trail shows what was decided even if
// enforcement fails or the process dies mid-enforce.
func (e *Engine) Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	dec, err := e.disp.Dispatch(ctx, ev)
	if dec != nil {
		e.enforce(ctx, ev, dec)
		// Project the real detection to the control plane (opt-in, best-effort,
		// additive to the local ledger) so fleet visibility, peer-UEBA and the
		// dead-man's-switch operate over real endpoint detections (D80).
		e.projectTelemetry(ctx, ev, dec)
	}
	return dec, err
}

// enforce dispatches a recorded Decision to the first enforcer that advertises
// its action, supplying the enforcement TARGET (the event's file path) for a
// TargetedEnforcer. The enforcement outcome is audited — a failure is
// high-severity and never silent (D14). With no enforcers this is a no-op
// (observe-only, D1).
func (e *Engine) enforce(ctx context.Context, ev *corev1.Event, dec *corev1.Decision) {
	for _, enf := range e.Enforcers {
		if !core.CanEnforce(enf, dec) {
			continue
		}
		var enfErr error
		if te, ok := enf.(core.TargetedEnforcer); ok {
			enfErr = te.EnforceTarget(ctx, dec, ev.GetFilesystem().GetResolvedPath())
		} else {
			enfErr = enf.Enforce(ctx, dec)
		}
		e.recordEnforcement(ctx, dec, enfErr)
		return // one enforcer per action
	}
}

func (e *Engine) recordEnforcement(ctx context.Context, dec *corev1.Decision, enfErr error) {
	entry := &core.Entry{
		AppendedAt: e.now().UTC(),
		Decision:   dec,
		Retention:  core.RetentionStandard,
	}
	if enfErr != nil {
		// A failed enforcement is auditable, never silence (D14).
		entry.OutcomeKind = "enforcement-failed"
		entry.OutcomeStage = enfErr.Error()
	} else {
		entry.OutcomeKind = "enforced"
	}
	// Best-effort: an audit-append failure here is itself logged by the caller's
	// logger via the dispatcher path for the decision; the enforcement record is
	// appended directly. If it fails, the decision is still recorded — the
	// enforcement outcome record is the additional, not the primary, trail.
	_ = e.ledger.Append(ctx, entry)
}

// NewFromWorker is the production constructor: it takes a started *privileged.Worker.
func NewFromWorker(w *privileged.Worker, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	return New(w, policy, ledger, logger, stageDeadline)
}
