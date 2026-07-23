package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
)

func memInjectPolicy(t *testing.T) *policy.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "meminject", "1", `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"suspected code injection","confidence":0.9} if { input.event.kind == "EVENT_KIND_MEMORY_INJECTION_SUSPECTED" }
decision := {"action":"ALLOW","reason":"ok","confidence":0.9} if { input.event.kind != "EVENT_KIND_MEMORY_INJECTION_SUSPECTED" }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// TestMemInjectionAlertsThroughEngine: a MEMORY_INJECTION_SUSPECTED event (a process with W+X memory)
// flows the real engine (real worker) + an alert policy → ALERT, and the engine does NOT try to read the
// flagged process's memory (it classifies the event metadata-only).
//
// Mutation (classifyStage does not treat the kind as metadata-only): classify tries to open the pid path
// → worker errors → no alert → this test FAILs.
func TestMemInjectionAlertsThroughEngine(t *testing.T) {
	ctx := context.Background()
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	eng := engine.New(worker, memInjectPolicy(t), &recLedger{}, nil, 10*time.Second)

	ev := &corev1.Event{
		Kind:    corev1.EventKind_EVENT_KIND_MEMORY_INJECTION_SUSPECTED,
		EventId: "meminject-test",
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid: 4242, ExecPath: "/usr/bin/victim"}},
	}
	dec, err := eng.Process(ctx, ev)
	if err != nil {
		t.Fatalf("process memory-injection event: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("memory-injection decision = %v, want ALERT", dec.GetAction())
	}
}
