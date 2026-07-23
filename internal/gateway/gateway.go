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
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/nips"
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

	// Identity is the resolved Zero-Trust context for an ACCESS request (D87): the
	// verified pseudonymous subject + role + device posture (D85/D86). nil for
	// egress/forward requests (unchanged). When set, Process resolves it into the
	// policy context and stamps the verified pseudonym as the Event subject.
	Identity *core.Context
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

	// telemetry projects a boundary-safe view of decisions to the control plane.
	// nil = no projection (the default); the local ledger is the system of record
	// (D30). Set via SetTelemetry.
	telemetry Projector

	// threatFeed, when set, is the NIPS-2 threat-intel engine: a threat-classify
	// stage matches each flow's destination/request metadata against it so the
	// policy can block a flow to a known-bad indicator. nil (unset) = no threat
	// matching. It is an ATOMIC pointer so a background feed reload (NIPS-2 hot
	// refresh) can swap in a new feed without a restart while requests read it
	// concurrently — the per-request pipeline build reads the CURRENT feed.
	threatFeed atomic.Pointer[nips.Feed]

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
	if logger == nil {
		logger = slog.Default()
	}
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
	// For an ACCESS request the subject is the VERIFIED identity pseudonym (D86/D87),
	// finally replacing the sha256(src-IP) non-identity (D84). For egress it stays the
	// pseudonymised source address.
	subject := pseudonym(r.SrcIP)
	if r.Identity != nil && r.Identity.Identity != "" {
		subject = r.Identity.Identity
	}
	return &corev1.Event{
		EventId:     newEventID(),
		AgentId:     "gateway",       // TODO(N1.2): real gateway node identity (T-017 analogue)
		ConnectorId: "gateway-proxy", // TODO(N1.2): the actual listener connector
		ObservedAt:  timestamppb.New(g.now().UTC()),
		Subject:     &corev1.Subject{PseudonymousId: subject},
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
	// NIPS-2 content signatures: the worker also matched the operator ruleset over the
	// body (behind the sandbox) and returned content-free ThreatMatches. Project them
	// onto the SAME threat axis the IOC metadata stage uses, so the policy prevents on a
	// body signature exactly as on a known-bad destination. APPEND (never overwrite): a
	// flow can trip both a metadata IOC and a content signature, and the policy must see
	// both — the net-threat stage appends its own matches to this.
	if tms := resp.GetThreatMatches(); len(tms) > 0 {
		if st.Threats == nil {
			st.Threats = &corev1.ThreatClassification{EventId: st.Event.GetEventId()}
		}
		st.Threats.Matches = append(st.Threats.Matches, tms...)
	}
	return core.Continue(), nil
}

// SetThreatFeed enables the NIPS-2 threat-intel engine: a threat-classify stage
// matches each flow's destination/request metadata against the feed, so the policy
// can block a flow to a known-bad indicator. Without a feed the engine is inert.
// SetThreatFeed sets (or hot-swaps) the feed atomically. Called once at startup and again by the
// NIPS-2 background reloader on each successful refresh; in-flight requests keep using whichever feed
// they loaded, and the next request picks up the new one.
func (g *Gateway) SetThreatFeed(f *nips.Feed) { g.threatFeed.Store(f) }

// BlockedDomain reports whether a domain is on the CURRENT IOC feed (a domain or a parent-suffix
// match) — the DNS sinkhole (NIPS-8) uses it so a hot-reloaded indicator is sinkholed with no restart.
// Nil feed (unconfigured) → nothing is blocked.
func (g *Gateway) BlockedDomain(name string) bool {
	f := g.threatFeed.Load()
	if f == nil {
		return false
	}
	for _, m := range f.Match(name, "", "") {
		if m.Category == nips.CategoryDomain {
			return true
		}
	}
	return false
}

// threatClassifyStage matches a flow's metadata against the IOC feed and records
// the threat matches on State — a distinct axis from the DLP body classification.
// It reads only Event metadata (host, dst IP, path), so it needs no worker and
// cannot fail on a parse; a match is a signal the policy acts on, never a block
// itself (fail open, D73).
type threatClassifyStage struct{ feed *nips.Feed }

func (threatClassifyStage) Name() string { return "net-threat" }

func (s threatClassifyStage) Run(_ context.Context, st *core.State) (core.Outcome, error) {
	ns := st.Event.GetNetwork()
	if ns == nil {
		return core.Continue(), nil
	}
	matches := s.feed.Match(ns.GetSniHost(), ns.GetDstIp(), ns.GetHttpPath())
	if len(matches) == 0 {
		return core.Continue(), nil
	}
	// APPEND to any existing threat classification (a content-signature stage may have
	// already recorded body matches on this flow) — overwriting would hide one axis of
	// threat from the policy. The two stages share one ThreatClassification.
	if st.Threats == nil {
		st.Threats = &corev1.ThreatClassification{EventId: st.Event.GetEventId()}
	}
	for _, m := range matches {
		st.Threats.Matches = append(st.Threats.Matches, &corev1.ThreatMatch{
			Category:    threatCategoryProto(m.Category),
			Confidence:  m.Confidence,
			IndicatorId: m.IndicatorID,
		})
	}
	return core.Continue(), nil
}

func threatCategoryProto(c nips.Category) corev1.ThreatCategory {
	switch c {
	case nips.CategoryDomain:
		return corev1.ThreatCategory_THREAT_CATEGORY_IOC_DOMAIN
	case nips.CategoryIP:
		return corev1.ThreatCategory_THREAT_CATEGORY_IOC_IP
	case nips.CategoryURI:
		return corev1.ThreatCategory_THREAT_CATEGORY_URI_SIGNATURE
	default:
		return corev1.ThreatCategory_THREAT_CATEGORY_UNSPECIFIED
	}
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
	// NIPS-2 threat-intel runs before the policy (when a feed is configured), so the
	// policy sees input.threat and can block a flow to a known-bad indicator.
	if f := g.threatFeed.Load(); f != nil {
		reg.Register(threatClassifyStage{feed: f})
	}
	reg.Register(g.policy)
	disp := core.NewDispatcher(&reg, g.deadline)
	disp.OnOutcome = core.NewAuditSink(g.ledger).Record
	disp.Logger = g.logger
	// For an ACCESS request, resolve the verified identity into the policy context
	// (D85/D87) via the SAME hook peer-UEBA uses (D53), so the policy authorizes on
	// input.context.{identity, role, device_posture}.
	if req.Identity != nil {
		ident := req.Identity
		disp.ResolveContext = func(*corev1.Event) *core.Context { return ident }
	}

	dec, err := disp.Dispatch(ctx, ev)
	if dec != nil {
		g.enforce(ctx, ev, dec)
		// Project a boundary-safe view to the control plane (opt-in, best-effort,
		// additive to the local ledger, D77).
		g.projectTelemetry(ctx, ev, dec)
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

// RecordTunnel appends a metadata-only entry for a flow the gateway tunneled
// WITHOUT inspecting it — the blind tunnel (D74) or a do-not-intercept host (D75).
// It records the destination host and the reason it was not inspected, and NOTHING
// else: no body, no URL path, no Decision (nothing was classified, so there is no
// verdict — representing it as an ALLOW would falsely claim it was inspected). So
// uninspected egress is VISIBLE in the audit trail rather than silent (D1/D17).
//
// Best-effort: a ledger append failure is logged, not fatal — the flow is happening
// regardless, and a recording failure must not sever connectivity (D30 when it
// works; a logged gap when it does not).
func (g *Gateway) RecordTunnel(ctx context.Context, host, reason string) {
	entry := &core.Entry{
		AppendedAt:   g.now().UTC(),
		Retention:    core.RetentionStandard,
		OutcomeKind:  "tunneled",
		OutcomeStage: host + " (" + reason + ")",
	}
	if err := g.ledger.Append(ctx, entry); err != nil {
		g.logger.Warn("gateway: recording a tunneled flow failed (flow proceeds, audit gap logged)",
			"err", err, "host", host, "reason", reason)
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
