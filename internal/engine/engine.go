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
	path := s.Event.GetFilesystem().GetResolvedPath()
	if path == "" {
		return core.Outcome{}, fmt.Errorf("classify: event carries no resolvable path")
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
	disp *core.Dispatcher
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
	return &Engine{disp: disp}
}

// Process runs one event through the pipeline and returns the Decision. A
// recording failure surfaces as an error alongside any decision (the caller must
// know the audit did not land), exactly as the dispatcher contracts.
func (e *Engine) Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	return e.disp.Dispatch(ctx, ev)
}

// NewFromWorker is the production constructor: it takes a started *privileged.Worker.
func NewFromWorker(w *privileged.Worker, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	return New(w, policy, ledger, logger, stageDeadline)
}
