package core_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// fakeProcEnforcer REUSES the existing TargetedEnforcer contract for process control: it
// resolves target = pid to a running process (here, records it) and carries out the
// verdict. No new enforcer interface — the process domain is the third after files and
// flows, and the interface is unchanged.
type fakeProcEnforcer struct{ pid string }

func (*fakeProcEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_DENY_EXEC, corev1.Action_ACTION_KILL_PROCESS}
}
func (*fakeProcEnforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("process enforcer needs a pid target")
}
func (f *fakeProcEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	f.pid = target
	return nil
}

var _ core.TargetedEnforcer = (*fakeProcEnforcer)(nil)

// THE FITNESS PROOF (Phase E, mirroring D69/D53): a process-exec Event flows through the
// UNCHANGED core.Dispatcher, is decided by a behavioral policy and audited, and the verdict
// is carried out by the EXISTING enforcer interface via target = pid. Only the proto (a
// target variant + two actions) and the closed-set maps changed — Dispatcher, State, Stage,
// Registry, Enforcer interface, OnOutcome, and the ledger are all untouched. The closed
// action set (D14) is WIDENED by deliberate decision (T1), never opened.
func TestProcessEventFitsUnchangedDispatcher(t *testing.T) {
	ev := &corev1.Event{
		EventId: "exec-1",
		Kind:    corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Subject: &corev1.Subject{PseudonymousId: "host-7"},
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid: 4242, Ppid: 1200,
			ExecPath:   "/usr/bin/powershell",
			Args:       []string{"-enc", "SQBFAFgA"},
			ParentPath: "/usr/bin/soffice.bin", // an office app spawning a shell = suspicious lineage
		}},
	}

	var reg core.Registry
	// A behavioral policy: a LOLBin (powershell) spawned by an office app → KILL_PROCESS.
	reg.Register(stageFuncCore("behavioral", func(_ context.Context, st *core.State) (core.Outcome, error) {
		p := st.Event.GetProcess()
		action := corev1.Action_ACTION_ALLOW
		if strings.Contains(p.GetExecPath(), "powershell") && strings.Contains(p.GetParentPath(), "soffice") {
			action = corev1.Action_ACTION_KILL_PROCESS
		}
		return core.Decided(&corev1.Decision{
			DecisionId: "d1", EventId: st.Event.GetEventId(), Action: action,
			Confidence: 0.95, Reason: "LOLBin spawned by office document", PolicyId: "hips", PolicyVersion: "1",
		}), nil
	}))

	audited := 0
	d := core.NewDispatcher(&reg, time.Second)
	d.OnOutcome = func(context.Context, *core.State, core.Outcome) error { audited++; return nil }

	dec, err := d.Dispatch(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_KILL_PROCESS {
		t.Fatalf("action=%v, want KILL_PROCESS — the exec event did not flow through the dispatcher", dec.GetAction())
	}
	if audited == 0 {
		t.Error("the process decision was not audited via the existing OnOutcome sink")
	}
	if err := core.ValidateDecision(dec, true); err != nil {
		t.Errorf("KILL_PROCESS decision failed validation — the closed set did not accept the new verb: %v", err)
	}

	// The process enforcer reuses the EXISTING TargetedEnforcer, acting on the pid.
	pe := &fakeProcEnforcer{}
	if !core.CanEnforce(pe, dec) {
		t.Fatal("process enforcer does not advertise the KILL_PROCESS verdict")
	}
	if err := pe.EnforceTarget(context.Background(), dec, "4242"); err != nil {
		t.Fatal(err)
	}
	if pe.pid != "4242" {
		t.Errorf("process enforcer acted on target %q, want the pid '4242'", pe.pid)
	}
}

// ProcessSubject carries exec METADATA only — never process memory or file content
// (D10/D29); both new verbs validate under the closed set.
func TestProcessContractBoundaries(t *testing.T) {
	fields := (&corev1.ProcessSubject{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		if strings.Contains(name, "memory") || strings.Contains(name, "content") || name == "payload" {
			t.Errorf("ProcessSubject exposes %q — process memory/content must never be an Event field (D10/D29)", name)
		}
	}
	for _, a := range []corev1.Action{corev1.Action_ACTION_DENY_EXEC, corev1.Action_ACTION_KILL_PROCESS} {
		dec := &corev1.Decision{
			DecisionId: "d", EventId: "e", Action: a,
			Confidence: 0.5, Reason: "r", PolicyId: "p", PolicyVersion: "1",
		}
		if err := core.ValidateDecision(dec, true); err != nil {
			t.Errorf("action %v not accepted by the closed set: %v", a, err)
		}
	}
}
