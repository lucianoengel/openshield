package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

func stateWith(hits ...*corev1.LocalMatch) *core.State {
	return &core.State{
		Event: &corev1.Event{
			EventId: "e1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		},
		Classification: &corev1.LocalClassification{EventId: "e1", Matches: hits},
	}
}

func cpfMatch(conf float64) *corev1.LocalMatch {
	return &corev1.LocalMatch{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: conf}
}

func mustDefault(t *testing.T) *policy.Stage {
	t.Helper()
	s, err := policy.NewDefault(context.Background())
	if err != nil {
		t.Fatalf("loading default policy: %v", err)
	}
	return s
}

func decide(t *testing.T, s *policy.Stage, st *core.State) *corev1.Decision {
	t.Helper()
	out, err := s.Run(context.Background(), st)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Kind != core.OutcomeDecided || out.Decision == nil {
		t.Fatalf("expected a decided outcome, got %v", out.Kind)
	}
	return out.Decision
}

// Task 1.3 / 4.x — the load-bearing property. A policy that reaches the network
// or the clock must fail to LOAD, not evaluate. Asserts behaviour, so it still
// guards after an OPA upgrade adds new builtins.
func TestForbiddenBuiltinsRejected(t *testing.T) {
	cases := map[string]string{
		"network": `package openshield
import rego.v1
decision := d if { http.send({"method":"get","url":"http://x"}); d := {"action":"ALLOW"} }`,
		"clock": `package openshield
import rego.v1
decision := d if { t := time.now_ns(); d := {"action":"ALLOW","reason":sprintf("%d",[t])} }`,
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := policy.New(context.Background(), "t", "1", mod)
			if err == nil {
				t.Fatalf("a policy using the %s was loaded — the capability set is not "+
					"restricting it, so distributed policy would be able to reach out", name)
			}
		})
	}
}

// A pure policy using only allowed builtins must still load and run.
func TestPurePolicyLoads(t *testing.T) {
	mod := `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"x"} if { some h in input.classification; h.confidence > 0.5 }`
	if _, err := policy.New(context.Background(), "t", "1", mod); err != nil {
		t.Fatalf("a pure policy failed to load: %v", err)
	}
}

// Task 4.1
func TestCPFHitAlerts(t *testing.T) {
	d := decide(t, mustDefault(t), stateWith(cpfMatch(0.95)))
	if d.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("action = %v, want ALERT", d.GetAction())
	}
	if d.GetPolicyId() != policy.DefaultID || d.GetPolicyVersion() != policy.DefaultVersion {
		t.Errorf("policy id/version not stamped: %q %q", d.GetPolicyId(), d.GetPolicyVersion())
	}
	if d.GetDecisionId() == "" || d.GetDecidedAt() == nil {
		t.Error("decision_id / decided_at not set by the Go layer")
	}
}

// Task 4.2 — determinism. Same input twice → equivalent Decisions (excluding the
// deliberately non-deterministic id/timestamp).
func TestDeterministic(t *testing.T) {
	s := mustDefault(t)
	a := decide(t, s, stateWith(cpfMatch(0.95)))
	b := decide(t, s, stateWith(cpfMatch(0.95)))
	if err := core.DecisionsEquivalent(a, b); err != nil {
		t.Errorf("same input produced different decisions: %v", err)
	}
	if a.GetDecisionId() == b.GetDecisionId() {
		t.Error("decision_id should be fresh per evaluation; determinism must come from " +
			"the policy being pure, not from a fixed id")
	}
}

// Task 4.3 — an unknown action is a failure, never a silent ALLOW.
func TestUnknownActionFails(t *testing.T) {
	mod := `package openshield
import rego.v1
decision := {"action":"UPLOAD_TO_URL","reason":"evil"}`
	s, err := policy.New(context.Background(), "t", "1", mod)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Run(context.Background(), stateWith(cpfMatch(0.95)))
	if err == nil {
		t.Fatal("a bogus action produced no error — a closed action set must reject it")
	}
	if out.Kind == core.OutcomeDecided {
		t.Error("a bogus action was turned into a Decision; it must be a failed outcome, not ALLOW")
	}
	if !strings.Contains(err.Error(), "UPLOAD_TO_URL") {
		t.Errorf("error should name the bad action: %v", err)
	}
}

// Task 4.4 — every enum action (except the unspecified zero) is mapped and
// round-trips.
func TestActionMappingIsComplete(t *testing.T) {
	for name, action := range policy.MappedActionsForTest() {
		if action == corev1.Action_ACTION_UNSPECIFIED {
			t.Errorf("%q maps to ACTION_UNSPECIFIED; a policy must not be able to select it", name)
		}
	}
	// Every non-zero enum value must appear exactly once.
	seen := map[corev1.Action]int{}
	for _, a := range policy.MappedActionsForTest() {
		seen[a]++
	}
	for a := range corev1.Action_name {
		act := corev1.Action(a)
		if act == corev1.Action_ACTION_UNSPECIFIED {
			continue
		}
		if seen[act] != 1 {
			t.Errorf("%v is mapped %d times, want exactly 1 — adding an enum value "+
				"without a mapping must fail here", act, seen[act])
		}
	}
}

// Task 4.5 — a policy that matches nothing is an explicit reasoned ALLOW.
func TestNoMatchIsReasonedAllow(t *testing.T) {
	// A policy whose `decision` is undefined for this input.
	mod := `package openshield
import rego.v1
decision := {"action":"ALERT"} if { input.event.kind == "NEVER" }`
	s, err := policy.New(context.Background(), "t", "1", mod)
	if err != nil {
		t.Fatal(err)
	}
	d := decide(t, s, stateWith(cpfMatch(0.95)))
	if d.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("action = %v, want ALLOW when no rule matched", d.GetAction())
	}
	if !strings.Contains(d.GetReason(), "no policy rule matched") {
		t.Errorf("reason = %q, want it to say no rule matched — distinguishable from an "+
			"affirmative allow", d.GetReason())
	}
}

// Task 4.6 — no Decision is ever emitted with confidence 1.0, even when the
// policy asserts certainty. The clamp must actually run on the policy's value,
// so this test first proves the policy's confidence is READ (a sub-certain value
// flows through unchanged) and only then that certainty is clamped. Without the
// first half, the test could pass merely because the policy value was ignored —
// which is exactly the bug this replaced.
func TestConfidenceIsNeverCertainty(t *testing.T) {
	read := func(t *testing.T, conf string) float64 {
		mod := `package openshield
import rego.v1
decision := {"action":"ALERT","confidence":` + conf + `,"reason":"x"}`
		s, err := policy.New(context.Background(), "t", "1", mod)
		if err != nil {
			t.Fatal(err)
		}
		// Classification max is 0.10 here, distinct from the policy values, so a
		// fallback would be detectable.
		return decide(t, s, stateWith(cpfMatch(0.10))).GetConfidence()
	}

	if got := read(t, "0.4"); got != 0.4 {
		t.Fatalf("policy confidence 0.4 came back as %v — the policy's value is not being "+
			"read (OPA returns json.Number), so the clamp below would be untested", got)
	}
	if got := read(t, "1.0"); got >= 1.0 {
		t.Errorf("confidence = %v; a Decision must never report certainty (D4)", got)
	}
}
