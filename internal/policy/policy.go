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
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

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
		action, reason, conf, err := evalCandidate(st, rs)
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

// evalCandidate turns a member's Rego result into an (action, reason, confidence),
// or an explicit reasoned ALLOW when no rule matched — the single-policy behavior,
// now per-member.
func evalCandidate(st *core.State, rs rego.ResultSet) (corev1.Action, string, float64, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		// No rule matched. In observe-only mode the honest default is ALLOW, but an
		// EXPLICIT allow with a reason — distinguishable in the ledger from a policy
		// that affirmatively allowed.
		return corev1.Action_ACTION_ALLOW, "no policy rule matched", maxClassificationConfidence(st), nil
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
