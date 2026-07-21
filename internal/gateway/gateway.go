// Package gateway assembles the NETWORK pipeline — the network analogue of
// internal/engine (the endpoint walking skeleton, D48/D62).
//
// Given a network request whose plaintext body the gateway holds, it classifies
// the BODY in-process (reusing internal/classify), projects the result to a
// content-free classification (D10/D29), runs the network Event through the
// EXISTING core.Dispatcher (a body-classify stage + the OPA policy stage) with the
// EXISTING audit sink, and — observe-only by default (D1) — dispatches the verdict
// to a registered flow enforcer keyed by flow_id (D69).
//
// The body is classified IN THE SANDBOXED WORKER, not in this process (D72,
// closing D71). The gateway is network-capable, and a parser bug in a
// network-capable process is RCE — the exact danger the worker's seccomp/
// no-network sandbox (D29/D35) removes. The gateway holds the body only to proxy
// it and to hand it to the worker; it does not link the parser (asserted by a
// dependency-graph test).
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// classifier is the subset of the worker the gateway needs — the SAME private
// interface the engine holds, so a *privileged.Worker satisfies both. An
// interface so the body-classify stage is testable without spawning a process,
// and so the gateway's dependency graph contains no parser (D72).
type classifier interface {
	Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)
}

// Request is one network request the gateway is deciding on. Body is the plaintext
// the gateway holds; it is classified in-process and NEVER placed in the Event,
// the Decision, or the ledger (D10/D29).
type Request struct {
	FlowID    string
	SrcIP     string
	SrcPort   uint32
	DstIP     string
	DstPort   uint32
	Protocol  string
	Host      string
	Method    string
	Path      string
	Direction corev1.NetworkDirection
	Body      []byte
}

// Gateway runs the assembled network pipeline for one request.
type Gateway struct {
	classifier classifier
	policy     core.Stage
	ledger     core.Ledger
	deadline   time.Duration
	logger     *slog.Logger
	now        func() time.Time

	// maxBytes caps how much of a body the worker parses (decompression-bomb
	// ceiling, D13). Zero lets the worker apply its own default.
	maxBytes uint64

	// Enforcers carry out Decisions post-decision. EMPTY by default — observe-only
	// (D1): the gateway decides and records, and enforces nothing until a flow
	// enforcer is registered. Enforcement is CONTAINMENT after detection, not
	// prevention (D16).
	Enforcers []core.Enforcer
}

// New assembles the network pipeline: classify-body (via the sandboxed worker) →
// policy → decide, with the audit sink recording every terminal outcome. The
// classifier is an interface so the parser is not linked into the gateway process
// (D72) and so the assembly is testable without spawning a worker.
func New(c classifier, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Gateway {
	return &Gateway{
		classifier: c,
		policy:     policy,
		ledger:     ledger,
		deadline:   stageDeadline,
		logger:     logger,
		now:        time.Now,
	}
}

// NewFromWorker is the production constructor: it takes a started
// *privileged.Worker, so body classification runs in the seccomp/no-network
// sandbox (D72). Mirrors engine.NewFromWorker.
func NewFromWorker(w *privileged.Worker, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Gateway {
	return New(w, policy, ledger, logger, stageDeadline)
}

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "evt_" + hex.EncodeToString(b[:])
}

// pseudonym derives a stable pseudonymous id from a network identifier, so the
// raw source address does not become the subject id (D23). It is one-way: the
// mapping back to an identity is a deployer concern behind an audited lookup, not
// the event stream's job.
func pseudonym(raw string) string {
	sum := sha256.Sum256([]byte("gateway-subject:" + raw))
	return "sub_" + hex.EncodeToString(sum[:12])
}

// toEvent builds a NetworkSubject Event carrying METADATA ONLY (D69). The body is
// deliberately absent — it is classified in the gateway process and never leaves
// it (D10/D29).
func (g *Gateway) toEvent(r *Request) *corev1.Event {
	return &corev1.Event{
		EventId:     newEventID(),
		AgentId:     "gateway",       // TODO(N1.2): real gateway node identity (T-017 analogue)
		ConnectorId: "gateway-proxy", // TODO(N1.2): the actual listener connector
		ObservedAt:  timestamppb.New(g.now().UTC()),
		Subject:     &corev1.Subject{PseudonymousId: pseudonym(r.SrcIP)},
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Kind:        corev1.EventKind_EVENT_KIND_HTTP_REQUEST,
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			FlowId:     r.FlowID,
			SrcIp:      r.SrcIP,
			SrcPort:    r.SrcPort,
			DstIp:      r.DstIP,
			DstPort:    r.DstPort,
			Protocol:   r.Protocol,
			SniHost:    r.Host,
			HttpMethod: r.Method,
			HttpPath:   r.Path,
			Direction:  r.Direction,
		}},
	}
}

// bodyClassifyStage hands THIS request's body to the sandboxed worker and puts
// the result on State — the network analogue of the engine's classifyStage. The
// plaintext is HELD by the gateway (it read it off the socket) but PARSED by the
// worker (D72), and the body is never in the Event (D10/D29). Content-free:
// type + confidence + count per occurrence, matched text NEVER attached — the
// worker never returns matched content across the IPC.
type bodyClassifyStage struct {
	c        classifier
	body     []byte
	maxBytes uint64
}

func (bodyClassifyStage) Name() string { return "net-classify" }

func (s bodyClassifyStage) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	resp, err := s.c.Classify(ctx, &corev1.ClassifyRequest{
		RequestId: st.Event.GetEventId(),
		EventId:   st.Event.GetEventId(),
		Subject:   &corev1.ClassifyRequest_Content{Content: s.body},
		MaxBytes:  s.maxBytes,
	})
	if err != nil {
		// A worker failure is NOT "nothing found" — surface it so a failed parse
		// is auditable, never a silent clean result (D17).
		return core.Outcome{}, fmt.Errorf("net-classify: worker: %w", err)
	}
	if resp.GetError() != "" {
		return core.Outcome{}, fmt.Errorf("net-classify: worker reported: %s", resp.GetError())
	}
	lc := &corev1.LocalClassification{EventId: st.Event.GetEventId()}
	for _, h := range resp.GetHits() {
		for i := uint32(0); i < h.GetCount(); i++ {
			lc.Matches = append(lc.Matches, &corev1.LocalMatch{
				DetectorType: h.GetDetectorType(),
				Confidence:   h.GetConfidence(),
				// MatchedText deliberately empty — no content crossed the IPC.
			})
		}
	}
	st.Classification = lc
	return core.Continue(), nil
}

// Process runs one request through the pipeline, records the Decision, then — if
// an enforcer can carry out its action — enforces it POST-DECISION. The Decision
// is recorded (by the audit sink) BEFORE enforcement is attempted, so the trail
// shows what was decided even if enforcement fails or the process dies mid-enforce
// (same ordering as the engine).
//
// The dispatcher is built per request because the body-classify stage closes over
// THIS request's plaintext (the body cannot come from the Event, D10/D29). Cheap
// enough for the skeleton; a production proxy would hoist the stage graph and pass
// the body through a request-scoped seam — noted, not premature-optimised.
func (g *Gateway) Process(ctx context.Context, req *Request) (*corev1.Decision, error) {
	ev := g.toEvent(req)

	var reg core.Registry
	reg.Register(bodyClassifyStage{c: g.classifier, body: req.Body, maxBytes: g.maxBytes})
	reg.Register(g.policy)
	disp := core.NewDispatcher(&reg, g.deadline)
	disp.OnOutcome = core.NewAuditSink(g.ledger).Record
	disp.Logger = g.logger

	dec, err := disp.Dispatch(ctx, ev)
	if dec != nil {
		g.enforce(ctx, ev, dec)
	}
	return dec, err
}

// enforce dispatches a recorded Decision to the first enforcer that advertises its
// action, supplying the enforcement TARGET (the flow_id) for a TargetedEnforcer —
// the network analogue of the engine supplying the file path. The enforcement
// outcome is audited: a failure is high-severity and never silent (D14). With no
// enforcers this is a no-op (observe-only, D1).
func (g *Gateway) enforce(ctx context.Context, ev *corev1.Event, dec *corev1.Decision) {
	for _, enf := range g.Enforcers {
		if !core.CanEnforce(enf, dec) {
			continue
		}
		var enfErr error
		if te, ok := enf.(core.TargetedEnforcer); ok {
			enfErr = te.EnforceTarget(ctx, dec, ev.GetNetwork().GetFlowId())
		} else {
			enfErr = enf.Enforce(ctx, dec)
		}
		g.recordEnforcement(ctx, dec, enfErr)
		return // one enforcer per action
	}
}

func (g *Gateway) recordEnforcement(ctx context.Context, dec *corev1.Decision, enfErr error) {
	entry := &core.Entry{
		AppendedAt: g.now().UTC(),
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
	_ = g.ledger.Append(ctx, entry)
}
