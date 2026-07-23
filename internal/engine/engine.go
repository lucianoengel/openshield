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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// classifier is the subset of the worker the engine needs — an interface so the
// classify stage is testable without spawning a process.
type classifier interface {
	Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)
}

// ContentResolver yields the bytes to classify for a network event that carries content
// out-of-band — an SMTP message body — or nil for a metadata-only event (a DNS query). It is how
// content reaches the sandboxed worker WITHOUT entering the Event (D10/D29): a connector buffers
// the body, the engine forwards it to the worker over IPC, and the engine itself never parses it
// (the RCE-prone parsing stays in the worker sandbox, ENG-1).
type ContentResolver func(ev *corev1.Event) []byte

// contentHolder is a mutable indirection shared between the Engine and its classify stage, so a
// content resolver can be installed after New (like SetTelemetry) without changing New's signature.
type contentHolder struct{ resolve ContentResolver }

// classifyStage hands a subject to the unprivileged worker and puts the result on the pipeline
// State. It receives detector hits — type + confidence + count — NEVER matched content:
// LocalClassification's matched text stays in the worker (D29), so the classification this builds
// carries empty matched_text.
type classifyStage struct {
	w       classifier
	content *contentHolder
}

func (classifyStage) Name() string { return "classify" }

func (c classifyStage) Run(ctx context.Context, s *core.State) (core.Outcome, error) {
	// A DELETED file (HIPS-4 FIM) or a RANSOMWARE detection (HIPS-4) has no content to open:
	// classify it as metadata-only and let the policy decide on its path/kind. Opening the path
	// would make the worker error (the file is missing, or the canaries are encrypted) and the
	// signal would never reach the policy. Correct in general — these events carry no readable bytes.
	switch s.Event.GetKind() {
	case corev1.EventKind_EVENT_KIND_FILE_DELETED, corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED:
		// These carry a FilesystemSubject path but have no readable content (a deleted file; the
		// encrypted/deleted canary set) — classify metadata-only so the worker never tries to open it.
		// (A memory-injection event carries a ProcessSubject, not a path, so the fs==nil branch below
		// already classifies it metadata-only — no case needed here.)
		s.Classification = &corev1.LocalClassification{EventId: s.Event.GetEventId()}
		return core.Continue(), nil
	}
	fs := s.Event.GetFilesystem()
	if fs == nil {
		// A non-file event. It MAY still carry content out-of-band (an SMTP body): if a content
		// resolver yields bytes, classify them in the worker via inline Content (ENG-1) — the
		// engine forwards the bytes but does not parse them (D29). Otherwise it is a metadata-only
		// event (DNS/HTTP/exec/USB) and the policy decides on its metadata via buildInput — hand it
		// an EMPTY classification (D134). Not a skipped scan masquerading as "found nothing":
		// metadata-only events genuinely have no content, and a file event must still have a path.
		if c.content != nil && c.content.resolve != nil {
			if body := c.content.resolve(s.Event); len(body) > 0 {
				return c.classify(ctx, s, &corev1.ClassifyRequest{
					RequestId: s.Event.GetEventId(), EventId: s.Event.GetEventId(),
					Subject: &corev1.ClassifyRequest_Content{Content: body},
				})
			}
		}
		s.Classification = &corev1.LocalClassification{EventId: s.Event.GetEventId()}
		return core.Continue(), nil
	}
	path := fs.GetResolvedPath()
	if path == "" {
		return core.Outcome{}, fmt.Errorf("classify: file event carries no resolvable path")
	}
	return c.classify(ctx, s, &corev1.ClassifyRequest{
		RequestId: s.Event.GetEventId(), EventId: s.Event.GetEventId(),
		Subject: &corev1.ClassifyRequest_Path{Path: path},
	})
}

// classify runs one worker request and builds a content-free LocalClassification from its hits.
func (c classifyStage) classify(ctx context.Context, s *core.State, req *corev1.ClassifyRequest) (core.Outcome, error) {
	resp, err := c.w.Classify(ctx, req)
	if err != nil {
		// A worker failure is NOT "nothing found" — surface it so a failed parse
		// is auditable, never a silent clean result (D17).
		return core.Outcome{}, fmt.Errorf("classify: worker: %w", err)
	}
	if resp.GetError() != "" {
		return core.Outcome{}, fmt.Errorf("classify: worker reported: %s", resp.GetError())
	}
	// One match per hit occurrence, carrying detector type and confidence but EMPTY matched_text.
	// The policy aggregates by type into type+confidence+count, which is all it reads.
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

	// enforceAuditDropped counts enforcement-audit appends that failed (R34-7) — a
	// silently-dropped ledger append for an automated action would be a hole in the
	// evidentiary trail, so it is counted and logged instead.
	enforceAuditDropped atomic.Int64

	// subject is the device's canonical pseudonym (pseudonym.Of(agentID), IDENT-1),
	// agentID the raw provenance id. When set, Process stamps the Subject (and the
	// agent_id/observed_at provenance) of endpoint events (which the connectors leave
	// target-only) and validates them (XDR-3). Empty = unconfigured: no stamping, no
	// added validation (backward-compatible).
	subject string
	agentID string

	// telemetry projects real detections to the control plane. nil = no projection
	// (the default); the local ledger is the system of record (D30). Set via
	// SetTelemetry (D80).
	telemetry Projector

	// Enforcers carry out Decisions post-decision (Phase 2). EMPTY by default —
	// with no enforcers the engine is observe-only (D1): it decides and records,
	// and enforces nothing. Registering an enforcer turns enforcement on, per
	// action. Enforcement is CONTAINMENT after detection, not prevention (D16).
	Enforcers []core.Enforcer

	// content backs SetContentResolver: the classify stage consults it to obtain the body of a
	// network-content event (an SMTP message) for worker classification. nil resolve = no content
	// source (the default): network events are metadata-only (D134). Shared with classifyStage.
	content *contentHolder
}

// New assembles the pipeline: classify (via the worker) → policy → decide, with
// the audit sink recording every terminal outcome and the logger correlating it.
func New(w classifier, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	content := &contentHolder{}
	var reg core.Registry
	reg.Register(classifyStage{w: w, content: content})
	reg.Register(policy)
	disp := core.NewDispatcher(&reg, stageDeadline)
	disp.OnOutcome = core.NewAuditSink(ledger).Record
	disp.Logger = logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{disp: disp, ledger: ledger, now: time.Now, logger: logger, content: content}
}

// SetContentResolver installs the source of out-of-band content for network events (ENG-1): when a
// network connector (e.g. SMTP) delivers a message with a body, the resolver returns that body so
// the classify stage sends it to the sandboxed worker. Without it, network events are metadata-only.
func (e *Engine) SetContentResolver(r ContentResolver) { e.content.resolve = r }

// SetSubject configures the engine's device identity: it stores the CANONICAL
// pseudonym of agentID (pseudonym.Of, the one derivation the gateway, posture, and
// the entity model share). When set, Process attributes endpoint events to this
// device and enforces the event contract (XDR-3).
func (e *Engine) SetSubject(agentID string) {
	e.agentID = agentID
	e.subject = pseudonym.Of(agentID)
}

// attribute stamps the canonical device subject (and a timestamp) on an event that
// lacks them, then validates the event — so an endpoint event that the connectors
// produced target-only is attributed to the device entity and satisfies the
// contract. An engine with no configured subject leaves the event untouched
// (backward-compatible). A configured engine REJECTS an event that is still invalid
// after stamping, rather than processing a malformed one.
func (e *Engine) attribute(ev *corev1.Event) error {
	if e.subject == "" {
		return nil
	}
	if ev.GetSubject().GetPseudonymousId() == "" {
		ev.Subject = &corev1.Subject{PseudonymousId: e.subject}
	}
	if ev.GetAgentId() == "" {
		ev.AgentId = e.agentID
	}
	if ev.GetObservedAt() == nil {
		ev.ObservedAt = timestamppb.New(e.now().UTC())
	}
	return core.ValidateEvent(ev)
}

// Process runs one event through the pipeline, records the Decision, then — if an
// enforcer can carry out its action — enforces it POST-DECISION. The order is
// deliberate: the Decision is recorded (by the dispatcher's audit sink) BEFORE
// enforcement is attempted, so the trail shows what was decided even if
// enforcement fails or the process dies mid-enforce.
func (e *Engine) Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	if err := e.attribute(ev); err != nil {
		return nil, err
	}
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
			enfErr = te.EnforceTarget(ctx, dec, enforceTarget(ev))
		} else {
			enfErr = enf.Enforce(ctx, dec)
		}
		e.recordEnforcement(ctx, dec, enfErr)
		return // one enforcer per action
	}
}

// enforceTarget picks the enforcement TARGET for an event by its KIND: a process event acts on its
// PID (KILL_PROCESS / DENY_EXEC), a file event on its resolved path (quarantine / encrypt). Without
// this, every event yielded the (empty, for a process event) filesystem path, so a pid-based
// enforcer received "" and self-refused — HIPS containment could never act (HIPS-5).
func enforceTarget(ev *corev1.Event) string {
	if p := ev.GetProcess(); p != nil {
		pid := strconv.FormatInt(int64(p.GetPid()), 10)
		// Carry the observation-time start-time on the target so the kill enforcer can revalidate the
		// process identity and spare a recycled pid (HIPS-7). Bare pid when it is unknown (0).
		if p.GetStartTicks() > 0 {
			return pid + ":" + strconv.FormatUint(p.GetStartTicks(), 10)
		}
		return pid
	}
	return ev.GetFilesystem().GetResolvedPath()
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
	// R34-7: never silently drop the enforcement-audit append — these are exactly the
	// automated actions that must be evidentiary. On failure, LOG and COUNT it (the
	// decision itself is still recorded by the dispatcher path, so this is the
	// additional trail — but a dropped append is observable, not silence, D14).
	if err := e.ledger.Append(ctx, entry); err != nil {
		e.enforceAuditDropped.Add(1)
		e.logger.Error("engine: enforcement-audit append failed (recorded as dropped, decision still audited)",
			slog.Any("err", err), slog.String("outcome", entry.OutcomeKind))
	}
}

// EnforceAuditDropped is the count of enforcement-audit appends that failed — a
// non-zero value means some automated-action outcomes are missing from the trail.
func (e *Engine) EnforceAuditDropped() int64 { return e.enforceAuditDropped.Load() }

// NewFromWorker is the production constructor: it takes a started *privileged.Worker.
func NewFromWorker(w *privileged.Worker, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	return New(w, policy, ledger, logger, stageDeadline)
}
