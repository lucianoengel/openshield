package policy_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// recordingLedger captures appended entries. Local to this test — the core
// package's fake is unexported.
type recordingLedger struct{ entries []*core.Entry }

func (l *recordingLedger) Append(_ context.Context, e *core.Entry) error {
	cp := *e
	l.entries = append(l.entries, &cp)
	return nil
}
func (l *recordingLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{Consistent: true}, nil
}
func (l *recordingLedger) Close() error { return nil }

// classifyStage stands in for the worker→State bridge: it puts a classification
// on the State the policy will read.
type classifyStage struct{ hits []*corev1.LocalMatch }

func (classifyStage) Name() string { return "classify" }
func (c classifyStage) Run(_ context.Context, st *core.State) (core.Outcome, error) {
	st.Classification = &corev1.LocalClassification{EventId: st.Event.GetEventId(), Matches: c.hits}
	return core.Continue(), nil
}

// Task 5.2 — the stage produces a Decision that the audit sink records. This is
// the first time the full observe path exists end to end: classify → policy →
// decide → audit.
func TestPolicyDecisionReachesTheLedger(t *testing.T) {
	pol, err := policy.NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var r core.Registry
	r.Register(classifyStage{hits: []*corev1.LocalMatch{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95},
	}})
	r.Register(pol)

	led := &recordingLedger{}
	d := core.NewDispatcher(&r, time.Second)
	d.OnOutcome = core.NewAuditSink(led).Record

	dec, err := d.Dispatch(context.Background(), &corev1.Event{
		EventId: "e1", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("decision action = %v, want ALERT", dec.GetAction())
	}
	if len(led.entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1 — the Decision was not recorded", len(led.entries))
	}
	got := led.entries[0].Decision
	if got == nil || got.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("recorded decision = %v, want an ALERT Decision", got)
	}
	if got.GetPolicyId() != policy.DefaultID {
		t.Errorf("recorded policy_id = %q, want %q", got.GetPolicyId(), policy.DefaultID)
	}
}
