package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

type fakeProjector struct {
	events    []*corev1.Event
	decisions []*corev1.Decision
	err       error
}

func (p *fakeProjector) PublishEvent(_ context.Context, e *corev1.Event) error {
	p.events = append(p.events, e)
	return p.err
}
func (p *fakeProjector) PublishDecision(_ context.Context, d *corev1.Decision) error {
	p.decisions = append(p.decisions, d)
	return p.err
}

// A detection projects its Event (path retained — the fleet needs the file identity)
// and its Decision to the control plane (D80).
func TestEngineProjectsDetection(t *testing.T) {
	pr := &fakeProjector{}
	eng := engine.New(fakeWorker{hits: []*corev1.DetectorHit{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 1},
	}}, stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT}), nil
	}), &recLedger{}, nil, time.Second)
	eng.SetTelemetry(pr)

	if _, err := eng.Process(context.Background(), fsEvent("e1", "/home/y/customers.csv")); err != nil {
		t.Fatal(err)
	}
	if len(pr.events) != 1 || len(pr.decisions) != 1 {
		t.Fatalf("projected %d events / %d decisions, want 1 / 1", len(pr.events), len(pr.decisions))
	}
	if pr.events[0].GetFilesystem().GetResolvedPath() != "/home/y/customers.csv" {
		t.Errorf("projected event lost the file path — the fleet needs the file identity; got %q",
			pr.events[0].GetFilesystem().GetResolvedPath())
	}
}

// No projector configured → nothing projected (opt-in default; the single-host path
// is unchanged).
func TestEngineTelemetryOffByDefault(t *testing.T) {
	pr := &fakeProjector{}
	eng := engine.New(fakeWorker{hits: []*corev1.DetectorHit{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 1},
	}}, stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT}), nil
	}), &recLedger{}, nil, time.Second)
	// SetTelemetry NOT called.
	if _, err := eng.Process(context.Background(), fsEvent("e1", "/tmp/x")); err != nil {
		t.Fatal(err)
	}
	if len(pr.events)+len(pr.decisions) != 0 {
		t.Error("projected telemetry with no projector configured — projection must be opt-in")
	}
}

// A projection error does not fail Process; the local ledger still recorded.
func TestEngineTelemetryErrorDoesNotFailProcess(t *testing.T) {
	pr := &fakeProjector{err: errors.New("control plane unreachable")}
	led := &recLedger{}
	eng := engine.New(fakeWorker{hits: []*corev1.DetectorHit{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 1},
	}}, stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT}), nil
	}), led, nil, time.Second)
	eng.SetTelemetry(pr)

	if _, err := eng.Process(context.Background(), fsEvent("e1", "/tmp/x")); err != nil {
		t.Fatalf("a telemetry error failed Process: %v — projection must be best-effort", err)
	}
	if len(led.entries) == 0 {
		t.Error("the decision was not recorded locally despite a telemetry error (D30)")
	}
}
