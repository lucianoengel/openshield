package policy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// SEC-C: default-deny lived in the TEXT of the operator's Rego, not in the engine.
//
// `evalCandidate` answered ALLOW when no rule matched, and the access proxy grants on ALLOW. Every
// access policy in this repo therefore ends with a line like:
//
//	decision := {"action":"BLOCK", ...} if { not authorized }
//
// which is the entire security model of the gate, written as an ordinary-looking rule. Delete it, shadow
// it with an earlier rule, or fail to extend it when a new input shape arrives, and the proxy silently
// becomes default-ALLOW in front of internal services — with a diff showing only a removed line that a
// reviewer has to KNOW was load-bearing.

// authorizedOnly is a correct access policy with the deny line PRESENT.
const authorizedOnly = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not authorized }`

// denyLineDeleted is the same policy with its last line removed — the exact edit SEC-C describes. It is
// still valid Rego, still compiles, still allows the finance role, and says nothing about anyone else.
const denyLineDeleted = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized }`

func accessRequest(role string) *core.State {
	st := &core.State{
		Event: &corev1.Event{
			Kind:   corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
			Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: "payroll"}},
		},
	}
	if role != "" {
		st.Context = &core.Context{Identity: "user:someone", Role: role}
	}
	return st
}

// TestAnAccessPolicyMissingItsDenyLineStillDenies is the defect.
//
// Mutation: drop the noMatch field from NewAccess (or ignore it in evalCandidate) → the unmatched
// request is ALLOWED and the access proxy admits it → this FAILS.
func TestAnAccessPolicyMissingItsDenyLineStillDenies(t *testing.T) {
	s, err := policy.NewAccess(context.Background(), "access", "1", denyLineDeleted)
	if err != nil {
		t.Fatalf("a policy that simply says nothing about unauthorized callers should still LOAD — it "+
			"is the evaluation that must deny, not the load: %v", err)
	}

	dec := decide(t, s, accessRequest("marketing"))
	if dec.GetAction() == corev1.Action_ACTION_ALLOW {
		t.Fatalf("a role no rule mentions was ALLOWED (%q) — with the deny line deleted, default-deny "+
			"existed only in text that is no longer there, and the proxy grants on ALLOW",
			dec.GetReason())
	}
	// The refusal SAYS it came from the default, so the ledger distinguishes "the policy denied you"
	// from "no rule covered you". Those are different operator problems: one is a decision, the other is
	// a policy that has a hole in it.
	if !strings.Contains(dec.GetReason(), "no policy rule matched") {
		t.Errorf("the denial reads %q — an operator cannot tell an authored denial from an unmatched "+
			"request", dec.GetReason())
	}

	// And the policy still WORKS: default-deny that denies everyone is not a fix, it is an outage.
	if got := decide(t, s, accessRequest("finance")).GetAction(); got != corev1.Action_ACTION_ALLOW {
		t.Errorf("the authorized role was refused (%v) — the no-match default must apply to requests "+
			"NO rule matched, not to every request", got)
	}
}

// TestACorrectAccessPolicyIsUnaffected. The fix must be invisible to a policy that already spells out
// its denial, or it changes behaviour nobody asked it to change.
func TestACorrectAccessPolicyIsUnaffected(t *testing.T) {
	s, err := policy.NewAccess(context.Background(), "access", "1", authorizedOnly)
	if err != nil {
		t.Fatal(err)
	}
	if got := decide(t, s, accessRequest("finance")).GetAction(); got != corev1.Action_ACTION_ALLOW {
		t.Errorf("finance was refused: %v", got)
	}
	dec := decide(t, s, accessRequest("marketing"))
	if dec.GetAction() == corev1.Action_ACTION_ALLOW {
		t.Errorf("marketing was allowed: %q", dec.GetReason())
	}
	// The authored reason survives — this request MATCHED a rule, so it must not be reported as unmatched.
	if !strings.Contains(dec.GetReason(), "not authorized") {
		t.Errorf("reason %q — an authored denial was replaced by the default's", dec.GetReason())
	}
}

// TestTheObservePipelineStillAllowsOnNoMatch guards the over-correction, which would be far more
// damaging than the bug.
//
// The same engine runs the endpoint DLP pipeline, where an unmatched event is the overwhelming majority
// of events — every ordinary file write on the machine. Denying those would not harden anything; it
// would stop the machine, and it would do so on the first deployment. Observe-first (D1) is the correct
// answer there and the correct answer here is the opposite, which is exactly why the answer belongs to
// the stage rather than to the engine.
//
// Mutation: make BLOCK the engine-wide no-match default rather than a per-stage one → this FAILS.
func TestTheObservePipelineStillAllowsOnNoMatch(t *testing.T) {
	// denyLineDeleted, deliberately: it is the module that says NOTHING about an unmatched request, so
	// what comes back is the engine's default rather than an authored decision. `authorizedOnly` would
	// not test this at all — its `not authorized` rule MATCHES a file event and returns an authored
	// BLOCK, which looks identical to the regression this is guarding against.
	s, err := policy.New(context.Background(), "observe", "1", denyLineDeleted)
	if err != nil {
		t.Fatal(err)
	}
	// A file event no rule mentions.
	st := &core.State{Event: &corev1.Event{Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED}}
	dec := decide(t, s, st)
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("an observe-first pipeline denied an event no rule matched (%v, %q) — that blocks "+
			"every ordinary file write on the host", dec.GetAction(), dec.GetReason())
	}
	if strings.Contains(dec.GetReason(), "access stage") {
		t.Errorf("the observe pipeline reported an access-stage reason: %q", dec.GetReason())
	}
}

// TestAnAccessPolicyThatAdmitsAnUnknownPrincipalIsRefusedAtLoad covers the half the no-match default
// cannot: a rule that is PRESENT and wrong.
//
// A policy allowing unconditionally, or whose predicate is vacuously true when the fields it reads are
// absent, MATCHES — so no default in the world fires. `role != "banned"` is the realistic shape: it
// reads like a denylist and admits every caller whose role could not be resolved at all.
//
// Mutation: drop the denyUnknownPrincipal call from NewAccess → both policies load → this FAILS.
func TestAnAccessPolicyThatAdmitsAnUnknownPrincipalIsRefusedAtLoad(t *testing.T) {
	for _, tc := range []struct{ name, module string }{
		{"unconditional allow", `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"open","confidence":0.9}`},
		{"a denylist that admits the unresolved", `package openshield
import rego.v1
authorized if { input.context.role != "banned" }
decision := {"action":"ALLOW","reason":"not banned","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"banned","confidence":0.9} if { not authorized }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.NewAccess(context.Background(), "access", "1", tc.module)
			if err == nil {
				t.Fatal("an access policy that ALLOWS a principal with no identity, no role and no " +
					"posture was accepted — it admits everyone who can complete the handshake, and it " +
					"does so by matching, so no default-deny can catch it")
			}
			if !errors.Is(err, policy.ErrAccessPolicyAdmitsUnknown) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestTheUnknownPrincipalProbeAcceptsARealPolicy. A probe that rejects correct policies is a probe that
// gets deleted, so the negative case is asserted as deliberately as the positive one — including the
// deny-line-deleted policy, which is INCOMPLETE but not permissive: it never allows an unknown
// principal, it simply says nothing, and the no-match default is what answers.
func TestTheUnknownPrincipalProbeAcceptsARealPolicy(t *testing.T) {
	for _, tc := range []struct{ name, module string }{
		{"complete", authorizedOnly},
		{"deny line deleted", denyLineDeleted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policy.NewAccess(context.Background(), "access", "1", tc.module); err != nil {
				t.Errorf("a policy that never admits an unknown principal was refused: %v", err)
			}
		})
	}
}
