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

// Stage evaluates a prepared policy and implements core.Stage.
type Stage struct {
	id      string
	version string
	query   rego.PreparedEvalQuery
	// newID and now are injected so the Decision's non-deterministic fields are
	// produced OUTSIDE the policy — the policy itself has no clock or randomness.
	newID func() string
	now   func() timestamp
}

// New prepares a policy stage from Rego source. A policy that references a
// forbidden builtin fails HERE, at preparation, not at evaluation time.
func New(ctx context.Context, id, version, module string) (*Stage, error) {
	q, err := rego.New(
		rego.Query(decisionRule),
		rego.Module("policy.rego", module),
		rego.Capabilities(restrictedCapabilities()),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: preparing %q: %w", id, err)
	}
	return &Stage{
		id: id, version: version, query: q,
		newID: newDecisionID,
		now:   nowUTC,
	}, nil
}

func (s *Stage) Name() string { return "policy" }

// Run evaluates the policy over the pipeline State and returns a Decision.
func (s *Stage) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	input := buildInput(st)

	rs, err := s.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return core.Outcome{}, fmt.Errorf("policy: eval: %w", err)
	}

	dec, err := s.decision(st, rs)
	if err != nil {
		// A broken policy result is a failure, surfaced. It is NOT coerced to
		// ALLOW: "the policy is broken" and "the policy allowed" demand
		// different responses, and a silent allow here would fail open.
		return core.Outcome{}, err
	}
	return core.Decided(dec), nil
}

// decision turns the Rego result set into a Decision, or an explicit reasoned
// ALLOW when no rule matched.
func (s *Stage) decision(st *core.State, rs rego.ResultSet) (*corev1.Decision, error) {
	base := &corev1.Decision{
		DecisionId:     s.newID(),
		EventId:        st.Event.GetEventId(),
		PolicyId:       s.id,
		PolicyVersion:  s.version,
		ContextVersion: st.ContextVersion(),
		DecidedAt:      s.now().proto(),
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		// No rule matched. In observe-only mode the honest default is ALLOW, but
		// an EXPLICIT allow with a reason — distinguishable in the ledger from a
		// policy that affirmatively allowed.
		base.Action = corev1.Action_ACTION_ALLOW
		base.Reason = "no policy rule matched"
		base.Confidence = maxClassificationConfidence(st)
		return base, nil
	}

	raw, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("policy: decision rule did not yield an object, got %T", rs[0].Expressions[0].Value)
	}

	actionName, _ := raw["action"].(string)
	action, ok := actionFromName(actionName)
	if !ok {
		return nil, fmt.Errorf("policy: unknown action %q — not in the closed action set (D14)", actionName)
	}
	base.Action = action

	if reason, ok := raw["reason"].(string); ok {
		base.Reason = reason
	}
	base.Confidence = confidenceFrom(raw, st)
	return base, nil
}

var _ core.Stage = (*Stage)(nil)
