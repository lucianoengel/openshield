// Package policy is the Decision stage: it evaluates a local Rego policy (D6)
// over classification evidence and emits a core Decision.
//
// The engine is instantiated with a RESTRICTED capability set — no network, no
// clock, no randomness. This is the load-bearing property of the package. It
// makes decisions deterministic (and therefore replayable, D27), removes
// http.send as an endpoint SSRF/exfil primitive, and — when policy distribution
// arrives in Phase 2 — makes a pushed policy unable to reach out regardless of
// what it contains. "The server coordinates, it does not control" becomes a
// capability boundary rather than a promise to review policy text.
//
// OPA lives here, never in internal/core: core must not gain a policy-engine or
// net/http dependency, the same boundary the ledger and transport keep
// (scripts/check-core-deps.sh).
package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/lucianoengel/openshield/internal/attack"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// decisionRule is where every policy must place its result.
const decisionRule = "data.openshield.decision"

// forbiddenBuiltins are deterministic builtins we still exclude because they are
// side-effecting or reach outside the evaluation. Nondeterministic builtins are
// excluded wholesale (the clock, randomness, http.send are all flagged
// nondeterministic by OPA); this list catches the deterministic-but-dangerous
// remainder.
var forbiddenBuiltins = map[string]bool{
	"opa.runtime": true, // exposes host environment/config
}

// restrictedCapabilities returns OPA capabilities with every nondeterministic
// builtin and every explicitly forbidden builtin removed.
//
// Filtering by the Nondeterministic flag rather than by an allowlist of names
// means an OPA upgrade that adds a new nondeterministic builtin (a new clock, a
// new network call) is excluded automatically — the guard does not depend on us
// having enumerated it.
func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	kept := caps.Builtins[:0:0]
	for _, b := range caps.Builtins {
		if b.Nondeterministic || forbiddenBuiltins[b.Name] {
			continue
		}
		kept = append(kept, b)
	}
	caps.Builtins = kept
	// allow_net nil + no http builtin means no network egress is even expressible.
	caps.AllowNet = []string{}
	return caps
}

// member is one policy module in a Stage: an independently-prepared query plus
// whether it is a compliance PACK (packs may not escalate to a process verb, D14/ADR-5).
type member struct {
	name   string
	query  rego.PreparedEvalQuery
	isPack bool
}

// Stage evaluates one or more prepared policy modules and implements core.Stage.
// A single-module Stage (New/NewDefault/NewPack) is a 1-member composite: its Run
// returns that module's Decision unchanged. A multi-module Stage (NewComposite)
// evaluates every member over the same input and combines their decisions under a
// most-restrictive-wins data-verb lattice (DLP-5b/ADR-5).
type Stage struct {
	id      string
	version string
	members []member
	// newID and now are injected so the Decision's non-deterministic fields are
	// produced OUTSIDE the policy — the policy itself has no clock or randomness.
	newID func() string
	now   func() timestamp

	// noMatch is what this stage decides when a module's rule body does not fire (SEC-C).
	//
	// It is a property of the STAGE, not of the module, because it is the stage that knows what the
	// decision is FOR. An observe-first DLP pipeline must not deny a file write nobody wrote a rule
	// about — that would block the machine. A Zero-Trust access gate must not admit a request nobody
	// wrote a rule about — that is the definition of the thing it exists to prevent. Same engine,
	// opposite correct answers, so the answer cannot live in the engine's default.
	//
	// Zero value is ACTION_ALLOW for the observe-first constructors; NewAccess sets BLOCK.
	noMatch corev1.Action
}

// prepare compiles one Rego module into a query under the restricted capabilities.
// A module that references a forbidden builtin fails HERE, at preparation.
func prepare(ctx context.Context, name, module string) (rego.PreparedEvalQuery, error) {
	q, err := rego.New(
		rego.Query(decisionRule),
		rego.Module("policy.rego", module),
		rego.Capabilities(restrictedCapabilities()),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("policy: preparing %q: %w", name, err)
	}
	return q, nil
}

// New prepares a single-module policy stage from Rego source. A policy that
// references a forbidden builtin fails HERE, at preparation, not at evaluation time.
func New(ctx context.Context, id, version, module string) (*Stage, error) {
	q, err := prepare(ctx, id, module)
	if err != nil {
		return nil, err
	}
	return &Stage{
		id: id, version: version,
		members: []member{{name: id, query: q}},
		newID:   newDecisionID,
		now:     nowUTC,
	}, nil
}

// ErrAccessPolicyAdmitsUnknown means a module offered as an access policy affirmatively ALLOWS a
// principal carrying no identity, no role and no posture.
var ErrAccessPolicyAdmitsUnknown = errors.New("policy: the access policy admits an unknown principal")

// NewAccess prepares an ACCESS-stage policy: no-match DENIES, and the module is proven to deny an
// unknown principal before this returns (SEC-C).
//
// The two halves close different holes and neither replaces the other.
//
// The no-match default handles the rule that is ABSENT — deleted, shadowed by an earlier rule, or never
// written for a case nobody thought of. Before this, the engine answered ALLOW and the access proxy
// grants on ALLOW, so an operator's Rego was the only thing standing between an unmatched request and
// the internal service behind the gate.
//
// The probe handles the rule that is PRESENT and wrong: a module whose author wrote an unconditional
// allow, or an `authorized` predicate that is vacuously true when the fields it reads are absent. A
// no-match default cannot see that, because such a policy matches.
//
// It runs at load, not at first request, for the reason the whole component is fail-closed: the failure
// mode of a Zero-Trust gate must be "does not start", never "starts and admits everyone".
func NewAccess(ctx context.Context, id, version, module string) (*Stage, error) {
	q, err := prepare(ctx, id, module)
	if err != nil {
		return nil, err
	}
	s := &Stage{
		id: id, version: version,
		members: []member{{name: id, query: q}},
		newID:   newDecisionID,
		now:     nowUTC,
		noMatch: corev1.Action_ACTION_BLOCK,
	}
	if err := s.denyUnknownPrincipal(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// unknownPrincipalStates are the canonical "we know nothing about who this is" requests.
//
// Both shapes are probed because they are different failures and a policy can pass one while failing
// the other. A NIL context is no identity resolved at all — the enrichment did not run, or ran and
// found nothing. A ZERO context is an identity that resolved to nothing: a caller authenticated at the
// transport, entitled to precisely nothing. A gate that admits either admits everyone who can complete
// a handshake.
//
// They are built through buildInput, the same function that assembles a real request's document, rather
// than as a hand-written map. A probe asserting against a shape the policy never actually sees is a
// probe that passes for the wrong reason — and the input shape has grown fields (risk, posture, response
// intent, CASB) several times, each of which would have silently drifted from a literal.
func unknownPrincipalStates() []*core.State {
	// Carries an id and a connector like any other event. This probe is never emitted, so nothing
	// downstream would have rejected it — but a synthetic event that could not survive
	// core.ValidateEvent is a synthetic event shaped differently from the real ones, which is the whole
	// thing this function is trying not to be. The fitness guard that requires provenance on every event
	// literal is right to insist here too.
	ev := &corev1.Event{
		EventId:     "policy-access-probe",
		ConnectorId: "policy.access.probe",
		Kind:        corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		Target:      &corev1.Event_Network{Network: &corev1.NetworkSubject{}},
	}
	return []*core.State{
		{Event: ev},
		{Event: ev, Context: &core.Context{}},
	}
}

// denyUnknownPrincipal evaluates the module against the canonical unknown principals and refuses one
// that allows any of them.
func (s *Stage) denyUnknownPrincipal(ctx context.Context) error {
	for _, st := range unknownPrincipalStates() {
		rs, err := s.members[0].query.Eval(ctx, rego.EvalInput(buildInput(st)))
		if err != nil {
			return fmt.Errorf("policy: evaluating the access policy against an unknown principal: %w", err)
		}
		action, reason, _, err := evalCandidate(st, rs, s.noMatch)
		if err != nil {
			return fmt.Errorf("policy: the access policy produced an unusable decision for an unknown "+
				"principal: %w", err)
		}
		if action == corev1.Action_ACTION_ALLOW {
			return fmt.Errorf("%w: a request with no identity, no role and no device posture was "+
				"ALLOWED (%q). An access policy that admits a caller it knows nothing about admits "+
				"everyone who can complete the handshake", ErrAccessPolicyAdmitsUnknown, reason)
		}
	}
	return nil
}

// NewComposite prepares default + selected packs (+ optional operator custom rules)
// as independent members, combined most-restrictive-wins (DLP-5b/ADR-5). The default
// is always the first member, so its protections (behavioral alerting, strong-detector
// alert) survive pack selection. An unknown pack name is an error, never a silent
// fallback. The composed bundle identity (default+pack+...) is stamped on the Decision.
func NewComposite(ctx context.Context, packNames []string, customModule string) (*Stage, error) {
	dq, err := prepare(ctx, "default", defaultPolicy)
	if err != nil {
		return nil, err
	}
	members := []member{{name: "default", query: dq}}
	names := []string{"default"}
	for _, pn := range packNames {
		module, ok := compliancePacks[pn]
		if !ok {
			return nil, fmt.Errorf("policy: unknown compliance pack %q (have %v)", pn, Packs())
		}
		pq, err := prepare(ctx, "pack:"+pn, module)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: pn, query: pq, isPack: true})
		names = append(names, pn)
	}
	if customModule != "" {
		cq, err := prepare(ctx, "custom", customModule)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: "custom", query: cq})
		names = append(names, "custom")
	}
	return &Stage{
		id:      CompositeID,
		version: strings.Join(names, "+"),
		members: members,
		newID:   newDecisionID,
		now:     nowUTC,
	}, nil
}

// CompositeID labels a multi-module Decision; the specific bundle is in PolicyVersion.
const CompositeID = "openshield.composite"

func (s *Stage) Name() string { return "policy" }

// Run evaluates every member over the same input and combines their decisions.
func (s *Stage) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	input := buildInput(st)

	cands := make([]candidate, 0, len(s.members))
	for _, m := range s.members {
		rs, err := m.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return core.Outcome{}, fmt.Errorf("policy: eval %q: %w", m.name, err)
		}
		action, reason, conf, err := evalCandidate(st, rs, s.noMatch)
		if err != nil {
			// A broken policy result is a failure, surfaced. It is NOT coerced to
			// ALLOW: "the policy is broken" and "the policy allowed" demand
			// different responses, and a silent allow here would fail open.
			return core.Outcome{}, fmt.Errorf("policy: %q: %w", m.name, err)
		}
		cands = append(cands, candidate{name: m.name, isPack: m.isPack, action: action, reason: reason, confidence: conf})
	}

	win, err := selectWinner(cands)
	if err != nil {
		return core.Outcome{}, err
	}
	return core.Decided(&corev1.Decision{
		DecisionId:     s.newID(),
		EventId:        st.Event.GetEventId(),
		PolicyId:       s.id,
		PolicyVersion:  s.version,
		ContextVersion: st.ContextVersion(),
		DecidedAt:      s.now().proto(),
		Action:         win.action,
		Reason:         win.reason,
		Confidence:     win.confidence,
		// XDR-4b: the ATT&CK techniques the EVIDENCE supported, from the same derivation that built
		// input.attack.techniques above — not from `rs`, the policy's own result.
		//
		// Reading a technique out of the policy result would be more flexible and would be wrong. A
		// module here is composed from a default pack, zero or more compliance packs and a custom
		// module (ADR-5), all operator-authored; if any of them could DECLARE a technique, then "what
		// did this asset evidence?" would be answered by whatever the rules asserted, and the
		// technique-sequence hunt in XDR-4b would correlate claims instead of signals. Policy decides
		// what to do about signals; it never decides what the signals were.
		Techniques: attack.IDs(attackSignals(st)),
	}), nil
}

// candidate is one member's decision, tagged so the combine can enforce the
// pack-cannot-escalate guard.
type candidate struct {
	name       string
	isPack     bool
	action     corev1.Action
	reason     string
	confidence float64
}

// evalCandidate turns a member's Rego result into an (action, reason, confidence), or the stage's
// configured no-match outcome when no rule fired — the single-policy behavior, now per-member.
func evalCandidate(st *core.State, rs rego.ResultSet, noMatch corev1.Action) (corev1.Action, string, float64, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		// NO RULE MATCHED, and what that means is the stage's to say (SEC-C).
		//
		// This used to be an unconditional ALLOW, which is right for observe-only and was wrong for the
		// access proxy — the proxy grants on ALLOW, so default-deny lived entirely in the text of the
		// operator's Rego. Removing or shadowing the `decision := BLOCK if { not authorized }` line
		// converted a default-deny gate into a default-allow one, and the diff showed only a deleted
		// line that a reviewer had to KNOW was the whole security model.
		//
		// Either way it is an EXPLICIT outcome with a reason, distinguishable in the ledger from a
		// policy that affirmatively decided.
		if noMatch == corev1.Action_ACTION_UNSPECIFIED {
			noMatch = corev1.Action_ACTION_ALLOW
		}
		return noMatch, noMatchReason(noMatch), maxClassificationConfidence(st), nil
	}
	raw, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return 0, "", 0, fmt.Errorf("decision rule did not yield an object, got %T", rs[0].Expressions[0].Value)
	}
	actionName, _ := raw["action"].(string)
	action, ok := actionFromName(actionName)
	if !ok {
		return 0, "", 0, fmt.Errorf("unknown action %q — not in the closed action set (D14)", actionName)
	}
	reason, _ := raw["reason"].(string)
	return action, reason, confidenceFrom(raw, st), nil
}

// dataRank orders the data-plane verbs most-restrictive-last (ADR-5). The second
// return is false for a non-data verb (a process-control verb or unspecified).
func dataRank(a corev1.Action) (int, bool) {
	switch a {
	case corev1.Action_ACTION_ALLOW:
		return 0, true
	case corev1.Action_ACTION_ALERT:
		return 1, true
	case corev1.Action_ACTION_REDIRECT:
		return 2, true
	case corev1.Action_ACTION_ENCRYPT_LOCAL:
		return 3, true
	case corev1.Action_ACTION_QUARANTINE_LOCAL:
		return 4, true
	case corev1.Action_ACTION_BLOCK:
		return 5, true
	}
	return 0, false
}

func isProcessVerb(a corev1.Action) bool {
	return a == corev1.Action_ACTION_DENY_EXEC || a == corev1.Action_ACTION_KILL_PROCESS
}

// selectWinner picks the composed decision. Data verbs combine most-restrictive-wins.
// A compliance PACK that yields a process-control verb is a hard error — a pack must
// never silently escalate to killing or denying a process (ADR-5). A process verb from
// the default/custom axis takes precedence over data verbs (a process event's KILL is
// not overridden by a pack's ALLOW); the two axes never actually co-occur for a
// well-formed event, so this is the formal statement of "they never combine".
func selectWinner(cands []candidate) (candidate, error) {
	var proc, best *candidate
	for i := range cands {
		c := &cands[i]
		if isProcessVerb(c.action) {
			if c.isPack {
				return candidate{}, fmt.Errorf("policy: compliance pack %q yielded process-control verb %s — "+
					"a pack must not escalate to a process action (ADR-5)", c.name, c.action)
			}
			if proc == nil {
				proc = c // first process verb wins; only one is expected per event
			}
			continue
		}
		if best == nil {
			best = c
			continue
		}
		r, _ := dataRank(c.action)
		br, _ := dataRank(best.action)
		if r > br {
			best = c
		}
	}
	if proc != nil {
		return *proc, nil
	}
	if best != nil {
		return *best, nil
	}
	return candidate{}, fmt.Errorf("policy: no candidate decision produced")
}

var _ core.Stage = (*Stage)(nil)

// noMatchReason states, in the ledger, what the absence of a matching rule meant here. Two different
// sentences because they are two different events: an observe-first pipeline saw nothing to say about,
// and an access gate refused a request nobody authorized.
func noMatchReason(a corev1.Action) string {
	if a == corev1.Action_ACTION_ALLOW {
		return "no policy rule matched"
	}
	return "no policy rule matched — the access stage denies by default (SEC-C)"
}
