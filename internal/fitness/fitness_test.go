package fitness_test

// This test package imports ONLY internal/core and internal/core/corev1 — NOTHING
// from internal/connectors, enforcers, classify, policy or store. That restraint
// is the proof: if adding a capability required reaching into one of those, this
// test could not be written using core alone, and it can. A reviewer who sees a
// capability-package import added here should reject it — the import would void
// exactly the claim the test makes.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// --- a whole capability, defined outside core, in this test only ---

// testConnector is an Event producer. A connector's entire job is to emit
// Events; it never classifies, decides or enforces.
type testConnector struct{}

func (testConnector) Produce() *corev1.Event {
	return &corev1.Event{
		EventId: "fitness-1", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
	}
}

// testStage is a Decision-producing stage.
type testStage struct{}

func (testStage) Name() string { return "fitness-policy" }
func (testStage) Run(_ context.Context, s *core.State) (core.Outcome, error) {
	return core.Decided(&corev1.Decision{
		DecisionId: "fd1", EventId: s.Event.GetEventId(),
		Action: corev1.Action_ACTION_ALERT, Confidence: 0.5,
	}), nil
}

// testEnforcer accepts a Decision and NOTHING else — it cannot see the connector
// that produced the event or the stage that decided.
type testEnforcer struct{ enforced []corev1.Action }

func (e *testEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_ALERT}
}
func (e *testEnforcer) Enforce(_ context.Context, d *corev1.Decision) error {
	e.enforced = append(e.enforced, d.GetAction())
	return nil
}

// TestCapabilityAddedFromOutsideCore is the fitness claim in executable form: a
// connector, stage and enforcer that exist nowhere in the shipped tree are wired
// through the public core contracts and carry an Event to an enforced Decision,
// with no edit to internal/core.
func TestCapabilityAddedFromOutsideCore(t *testing.T) {
	conn := testConnector{}
	var reg core.Registry
	reg.Register(testStage{})
	disp := core.NewDispatcher(&reg, time.Second)

	// Connector → Event → pipeline → Decision.
	dec, err := disp.Dispatch(context.Background(), conn.Produce())
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("decision action = %v, want ALERT", dec.GetAction())
	}

	// Decision → Enforcer (which sees only the Decision).
	enf := &testEnforcer{}
	if !core.CanEnforce(enf, dec) {
		t.Fatal("enforcer does not advertise the decision's action")
	}
	if err := enf.Enforce(context.Background(), dec); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if len(enf.enforced) != 1 || enf.enforced[0] != corev1.Action_ACTION_ALERT {
		t.Errorf("enforcer did not carry out the decision: %v", enf.enforced)
	}
}

// TestFitnessTestKnowsItsLimits guards the honesty caveat: the "necessary but not
// sufficient" verdict (D26 / T-004) must remain in the docs. If it were dropped
// while this green suite stayed, the suite would manufacture the false confidence
// the project was built to avoid.
func TestFitnessTestKnowsItsLimits(t *testing.T) {
	dec, err := os.ReadFile("../../docs/decisions.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), "necessary but not sufficient") {
		t.Error("the D26 'necessary but not sufficient' caveat is missing from docs/decisions.md — " +
			"a fitness test that lost its caveat is worse than none")
	}
	// The package doc must also carry the warning a reader of the test sees.
	self, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(self), "NECESSARY BUT NOT SUFFICIENT") {
		t.Error("the fitness package doc dropped its own caveat")
	}
}
