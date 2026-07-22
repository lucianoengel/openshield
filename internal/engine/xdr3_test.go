package engine_test

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// cleanWorker is a classifier that reports no hits — so the policy decides on an
// empty classification (the engine's attribution is what's under test).
type cleanWorker struct{}

func (cleanWorker) Classify(context.Context, *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return &corev1.ClassifyResponse{}, nil
}

func newAttributingEngine(t *testing.T, agentID string) *engine.Engine {
	t.Helper()
	pol, err := policy.NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(cleanWorker{}, pol, &recLedger{}, nil, time.Second)
	e.SetSubject(agentID)
	return e
}

// connectorEvent mimics what fanotify/filewatch produce: a target, but NO subject
// and NO observed_at.
func connectorEvent(id, path string) *corev1.Event {
	return &corev1.Event{
		EventId: id, ConnectorId: "fanotify", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind:   corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: path}}},
	}
}

// TestEngineStampsCanonicalSubject proves a configured engine stamps the canonical
// device pseudonym (and observed_at) on a connector event, so it passes validation.
func TestEngineStampsCanonicalSubject(t *testing.T) {
	e := newAttributingEngine(t, "agent-A")
	ev := connectorEvent("e1", "/home/u/x.txt")

	if _, err := e.Process(context.Background(), ev); err != nil {
		t.Fatalf("process a connector event: %v", err)
	}
	// The event was stamped in place with the canonical pseudonym.
	if got, want := ev.GetSubject().GetPseudonymousId(), pseudonym.Of("agent-A"); got != want {
		t.Fatalf("stamped subject = %q, want the canonical pseudonym %q", got, want)
	}
	if ev.GetObservedAt() == nil {
		t.Fatal("observed_at was not stamped")
	}
}

// TestEngineRejectsInvalidEvent proves a configured engine rejects an event that is
// still invalid after stamping (no target) rather than processing it.
func TestEngineRejectsInvalidEvent(t *testing.T) {
	e := newAttributingEngine(t, "agent-A")
	ev := &corev1.Event{EventId: "e2", ConnectorId: "fanotify", Purpose: corev1.Purpose_PURPOSE_DLP} // no target

	if _, err := e.Process(context.Background(), ev); err == nil {
		t.Fatal("a targetless event should be rejected by a configured engine")
	}
}

// TestUnconfiguredEngineUnchanged proves an engine with no configured subject does
// not stamp or reject — the pre-XDR-3 behavior.
func TestUnconfiguredEngineUnchanged(t *testing.T) {
	pol, err := policy.NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(cleanWorker{}, pol, &recLedger{}, nil, time.Second)
	// No SetSubject.
	ev := connectorEvent("e3", "/home/u/y.txt")
	if _, err := e.Process(context.Background(), ev); err != nil {
		t.Fatalf("unconfigured engine should process a subject-less event as before: %v", err)
	}
	if ev.GetSubject() != nil {
		t.Fatal("an unconfigured engine must not stamp a subject")
	}
}
