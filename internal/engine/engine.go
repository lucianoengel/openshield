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
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
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
	// onIntent is announced for each verified coordinated-response intent applied. nil = silent.
	onIntent func(*corev1.ResponseIntent)

	// KillSwitch, when set, stops this component ENFORCING without stopping it detecting (PLAT-9). Nil
	// means none was installed and enforcement behaves exactly as before: a component never given a
	// switch must enforce normally rather than silently do nothing.
	KillSwitch *core.KillSwitch
	// fleetControl is kept so its counters can be reported; see FleetControlCounts.
	fleetControl *intent.FleetControlSubscriber
	disp         *core.Dispatcher
	ledger       core.Ledger
	now          func() time.Time
	logger       *slog.Logger

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

	// exclusions is the PRIV-1 privacy exclusion set (D20): subjects the system must not observe at
	// all. Empty by default — no exclusion is configured until an operator writes one, and an empty
	// set changes nothing.
	//
	// It is consulted in ProcessObserved and NOWHERE ELSE. Process, the verdict entry, never applies
	// it: an exclusion that suppressed an exec-permission decision would resolve to ALLOW, turning a
	// break-time window into a nightly interval in which any binary runs. The requirement this
	// implements says an exclusion is "a privacy control, not a user-invokable DLP evasion", and
	// excluding a verdict would make it exactly that.
	exclusions core.ExclusionSet

	// excluded counts events an exclusion suppressed; exclusionsUnevaluable counts events an exclusion
	// COULD NOT BE EVALUATED for, because the subject identity carries no path (two of the three
	// fanotify forms do not — docs/spike-t005-fanotify.md). Those events ARE observed, which is the
	// safe direction for detection and the unsafe one for a privacy promise, so the count is the whole
	// point: it is what turns "personal folders are not observed" into a statement an operator can
	// check rather than one they have to believe (D31 — a gap must never be silent).
	excluded              atomic.Int64
	exclusionsUnevaluable atomic.Int64
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

// SetExclusions installs the privacy exclusion set (PRIV-1). Empty = nothing is excluded, which is
// the default and the pre-existing behaviour.
func (e *Engine) SetExclusions(s core.ExclusionSet) { e.exclusions = s }

// Excluded reports how many observed events an exclusion suppressed.
func (e *Engine) Excluded() int64 { return e.excluded.Load() }

// ExclusionsUnevaluable reports how many observed events carried no resolvable path while a PATH
// exclusion was configured — events that were observed because the exclusion could not be evaluated.
//
// An operator reading a non-zero number here is reading the exact size of the hole in the privacy
// claim they made. A time-window exclusion is never unevaluable (it needs only the timestamp), so
// this counter is specifically about the personal-folder half being conditional on coverage mode.
func (e *Engine) ExclusionsUnevaluable() int64 { return e.exclusionsUnevaluable.Load() }

// SetIntentResolver installs the source of the coordinated-response verb in effect for an event's subject
// (SOAR-7 / HIPS-3 inc 2b), so the local policy can refuse a CONTAINed entity's next exec INLINE rather
// than killing the process after it has already run.
//
// It resolves into the CLOSED typed Context, and the policy decides what the verb means: the control plane
// publishes data, the endpoint decides (T2/D14). An engine with no resolver, or a policy that does not read
// the field, is unaffected by any intent — by design.
func (e *Engine) SetIntentResolver(r func(subject string) (verb corev1.IntentVerb, intentID string, ok bool)) {
	e.disp.ResolveContext = func(ev *corev1.Event) *core.Context {
		subject := ev.GetSubject().GetPseudonymousId()
		if subject == "" {
			return nil
		}
		verb, intentID, ok := r(subject)
		if !ok {
			return nil
		}
		// Version carries the INTENT ID. That field exists so a replay can evaluate against the Context
		// that actually applied (D27), and it is already recorded on the Decision and in the ledger — so
		// stamping it here is what makes both the gateway's flow block and the endpoint's exec denial
		// traceable to ONE intent id (XDR-6) WITHOUT adding a hashed ledger column, which migration 001
		// warns would break chain continuity.
		return &core.Context{
			Version: intentID, ResponseIntent: verb, HasResponseIntent: true, ComputedAt: time.Now(),
		}
	}
}

// ContentResolver returns the installed resolver, so a second producer can CHAIN onto it rather than
// displace it. The seam holds exactly one function; without a way to read it, the second producer to
// install one silently breaks the first — a lost classification with no error.
func (e *Engine) ContentResolver() ContentResolver { return e.content.resolve }

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
	// PURPOSE, stamped here for the same reason the subject is: the connectors produce a TARGET, and the
	// provenance fields are the engine's to supply.
	//
	// This was missing, and the observe path was BROKEN AT THE BINARY LEVEL because of it — every
	// fanotify event failed validation with "missing provenance field: purpose" and never reached the
	// classifier. No package test caught it, because every engine test hand-builds an event with a
	// purpose already set: the tests verified the pipeline against events the connectors do not produce.
	// That is this project's own named failure — verifying against its own assumptions — and it took
	// running the shipped binary to see it (D296).
	if ev.GetPurpose() == corev1.Purpose_PURPOSE_UNSPECIFIED {
		ev.Purpose = corev1.Purpose_PURPOSE_DLP
	}
	return core.ValidateEvent(ev)
}

// Process runs one event through the pipeline, records the Decision, then — if an
// enforcer can carry out its action — enforces it POST-DECISION. The order is
// deliberate: the Decision is recorded (by the dispatcher's audit sink) BEFORE
// enforcement is attempted, so the trail shows what was decided even if
// enforcement fails or the process dies mid-enforce.
// ProcessObserved is the entry for producers that OBSERVE — the fanotify file path, the print and
// SMTP sources, the discovery sweep. It applies the privacy exclusion set (PRIV-1) and then hands off
// to Process. A suppressed event returns (nil, nil): no classification ran, so no content was read,
// and there is nothing to decide about.
//
// THE SPLIT FROM Process IS THE SECURITY BOUNDARY, not a convenience. Process is the entry for
// producers that need a VERDICT they will act on — the exec gate, the clipboard mediator — where a
// nil decision necessarily resolves to allow. An exclusion applied there would not stop observation,
// it would change the outcome, and a break-time window would become a nightly interval in which any
// binary runs, reachable by any user willing to wait until 12:00. The requirement this implements
// says an exclusion is "a privacy control, not a user-invokable DLP evasion"; suppressing a verdict
// is that evasion.
//
// A producer added later that calls Process rather than this gets the NON-excluded behaviour. That
// is the correct default to forget: the cost is observing something that could have been excluded,
// not opening a hole an attacker can walk through.
func (e *Engine) ProcessObserved(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	if e.isExcluded(ev) {
		e.excluded.Add(1)
		return nil, nil
	}
	return e.Process(ctx, ev)
}

// isExcluded evaluates the exclusion set against an event, BEFORE classification — so an excluded
// subject's bytes are never read (the classify stage is what resolves content, and Dispatch is what
// invokes it).
//
// The two halves behave differently and the difference is load-bearing:
//
//   - A TIME window needs only the event's timestamp, so it applies to every observed event whatever
//     identity form the subject carries. The break-time control is complete.
//   - A PATH prefix needs a resolved path, and two of the three fanotify subject identities carry
//     none (docs/spike-t005-fanotify.md). For those the exclusion CANNOT BE EVALUATED. The event is
//     observed — the safe direction for detection — and the fact is counted, because the alternative
//     is an operator telling a works council that personal folders are unobserved while some of them
//     are being read.
func (e *Engine) isExcluded(ev *corev1.Event) bool {
	// LOCAL time, explicitly. TimeWindow is documented as a daily LOCAL-time window and contains()
	// compares t.Hour()*60+t.Minute() — but AsTime() returns UTC, so passing it straight through would
	// evaluate a 12:00-13:00 lunch break against the UTC clock. The control would still "work": it
	// would exclude observation for an hour a day, at the wrong hour, and nothing would look broken.
	at := ev.GetObservedAt().AsTime().Local()
	if !ev.GetObservedAt().IsValid() {
		at = e.now()
	}
	// The time half first, and separately, because it is ALWAYS evaluable: an event carrying no path
	// is still correctly excluded during a break window rather than counted as an unevaluable gap.
	// Passing the empty path here matches no prefix — Excluded skips empty prefixes and no non-empty
	// prefix is a prefix of "" — so this tests the windows alone.
	if e.exclusions.Excluded("", at) {
		return true
	}
	if len(e.exclusions.PathPrefixes) == 0 {
		return false
	}
	path, err := core.ResolvedPath(ev)
	if err == nil {
		return e.exclusions.Excluded(path, at)
	}
	// Unevaluable — but only for a FILESYSTEM subject. A DNS query, a USB insert or an exec carries no
	// path because it is not about a file, and a personal-folder exclusion was never going to apply to
	// it; counting those would bury the real number under traffic that was never in scope and make the
	// counter read as a far bigger hole than it is.
	//
	// What IS counted: a file event whose subject identity carries no path (two of the three fanotify
	// forms — docs/spike-t005-fanotify.md), which is exactly the case where the operator's
	// personal-folder claim cannot be checked. Note the bound on the exposure: the classify stage
	// refuses a file event with no resolvable path, so no CONTENT is read for these either — what
	// escapes the exclusion is the event's metadata, not the file's bytes.
	if ev.GetFilesystem() != nil {
		e.exclusionsUnevaluable.Add(1)
	}
	return false
}

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
	// PLAT-9: the emergency disable. It sits HERE — between the Decision and the Enforcer — and nowhere
	// earlier, so classification, the policy and the ledger all still ran. Stop acting; keep seeing: the
	// record of what WOULD have been enforced is exactly what an operator needs afterwards.
	if suppressed, reason := e.KillSwitch.SuppressEnforcement(dec); suppressed {
		e.recordSuppression(ctx, dec, reason)
		return
	}
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

// PipelineMetrics exposes the dispatcher's outcome counters so something can actually report them.
//
// core.Metrics has counted Dispatched/Decided/Failed/TimedOut since the pipeline was written, and its
// comment states why the split matters: "Timeouts are counted separately from failures because a rising
// timeout rate is its own signal: it is the cheapest way to detect an adversary manufacturing fail-open
// bypasses (D17)."
//
// Nothing read them. The dispatcher is held in an unexported field, so the numbers were unreachable from
// outside this package — the detection D17 describes as cheapest was not available at any price. This is
// the accessor that makes it reachable; cmd/openshield-engine does the reporting.
func (e *Engine) PipelineMetrics() *core.Metrics {
	if e.disp == nil {
		return nil
	}
	return &e.disp.Metrics
}

// NewFromWorker is the production constructor: it takes a started *privileged.Worker.
func NewFromWorker(w *privileged.Worker, policy core.Stage, ledger core.Ledger, logger *slog.Logger, stageDeadline time.Duration) *Engine {
	return New(w, policy, ledger, logger, stageDeadline)
}

// recordSuppression audits an enforcement the emergency disable prevented (PLAT-9). Recorded
// INDIVIDUALLY, not merely as switch state: an operator asking "what did we not block during those forty
// minutes" needs a number and a reason, and a silent kill switch is indistinguishable from a product that
// has stopped working.
func (e *Engine) recordSuppression(ctx context.Context, dec *corev1.Decision, reason string) {
	e.recordEnforcement(ctx, dec, fmt.Errorf("enforcement SUPPRESSED by the emergency disable (%s) — "+
		"the decision stands and is recorded; nothing was enforced", reason))
}

// SubscribeFleetControl wires the ENDPOINT to fleet-wide operational control (PLAT-9), closing the gap
// D265 named: the kill switch reached server-side components through the configuration store, and
// endpoint agents do not read it — until this they were disabled only by a local break-glass file.
//
// The subscriber verifies the signature, refuses a replayed sequence, refuses an expired or
// unknown-version control, and only then drives the same KillSwitch a local file does. Everything it
// refuses leaves enforcement ON.
//
// bound is where the replay sequence is PERSISTED (SEC-B). A nil bound keeps it in memory, which means a
// restart replays every captured control until its TTL — the caller that passes nil is responsible for
// saying so at startup.
func (e *Engine) SubscribeFleetControl(conn *nats.Conn, key ed25519.PublicKey,
	bound natsx.SeqStore) (*nats.Subscription, error) {
	if e.KillSwitch == nil {
		return nil, errors.New("engine: no kill switch installed; refusing to accept fleet control that " +
			"would have nothing to act on")
	}
	var sub *intent.FleetControlSubscriber
	if bound == nil {
		sub = intent.NewFleetControlSubscriber(key, e.KillSwitch)
	} else {
		var err error
		if sub, err = intent.NewPersistentFleetControlSubscriber(key, e.KillSwitch, bound); err != nil {
			return nil, err
		}
	}
	e.fleetControl = sub
	return sub.Subscribe(conn)
}

// FleetControlCounts reports controls APPLIED and REJECTED by the fleet-control channel.
//
// The subscriber used to be constructed and discarded on the line above, so its counters — including
// Rejected, whose comment says "a forged-control flood must be observable, not silent" — were unreachable
// from anywhere (D418). Zero when no fleet control is subscribed.
func (e *Engine) FleetControlCounts() (applied, rejected int64) {
	if e.fleetControl == nil {
		return 0, 0
	}
	return e.fleetControl.Applied.Load(), e.fleetControl.Rejected.Load()
}
