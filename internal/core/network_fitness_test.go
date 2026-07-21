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

// fakeFlowEnforcer is a network enforcer that REUSES the existing TargetedEnforcer
// contract: it resolves target = flow_id to a live connection (here, just records
// it) and carries out the verdict. No new enforcer interface exists.
type fakeFlowEnforcer struct{ flowID string }

func (*fakeFlowEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_REDIRECT, corev1.Action_ACTION_BLOCK}
}
func (*fakeFlowEnforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("flow enforcer needs a flow target")
}
func (f *fakeFlowEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	f.flowID = target
	return nil
}

var _ core.TargetedEnforcer = (*fakeFlowEnforcer)(nil)

// 3.1 + 3.2 — THE FITNESS PROOF (D69, mirroring peer-UEBA's D53): a network Event
// flows through the UNCHANGED core.Dispatcher, is decided and audited, and the
// verdict is carried out by the EXISTING enforcer interface via target=flow_id.
// The Dispatcher, State, Stage, Registry, Enforcer interface, OnOutcome and
// ledger are all untouched — only the proto (a target variant + one action) and
// one validator line changed.
func TestNetworkEventFitsUnchangedDispatcher(t *testing.T) {
	ev := &corev1.Event{
		EventId: "flow-1",
		Kind:    corev1.EventKind_EVENT_KIND_HTTP_REQUEST,
		Subject: &corev1.Subject{PseudonymousId: "user-42"},
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			FlowId: "flow-1", DstIp: "203.0.113.9", DstPort: 443, Protocol: "tcp",
			SniHost: "paste.example.com", HttpMethod: "POST", HttpPath: "/upload",
			Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
		}},
	}

	var reg core.Registry
	// A network-classify stage (a plugin; the real one reads the body IN-PROCESS).
	reg.Register(stageFuncCore("net-classify", func(_ context.Context, _ *core.State) (core.Outcome, error) {
		return core.Continue(), nil
	}))
	// A policy stage reading the NETWORK metadata and emitting a network verdict.
	reg.Register(stageFuncCore("policy", func(_ context.Context, st *core.State) (core.Outcome, error) {
		n := st.Event.GetNetwork()
		action := corev1.Action_ACTION_ALLOW
		if n.GetHttpMethod() == "POST" && strings.Contains(n.GetHttpPath(), "upload") {
			action = corev1.Action_ACTION_REDIRECT // coach the user, don't silently block
		}
		return core.Decided(&corev1.Decision{
			DecisionId: "d1", EventId: st.Event.GetEventId(), Action: action,
			Confidence: 0.9, Reason: "egress upload to paste site", PolicyId: "net", PolicyVersion: "1",
		}), nil
	}))

	// The EXISTING dispatcher and outcome sink — unchanged.
	audited := 0
	d := core.NewDispatcher(&reg, time.Second)
	d.OnOutcome = func(context.Context, *core.State, core.Outcome) error { audited++; return nil }

	dec, err := d.Dispatch(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_REDIRECT {
		t.Fatalf("action=%v, want REDIRECT — the network event did not flow through the dispatcher", dec.GetAction())
	}
	if audited == 0 {
		t.Error("the network decision was not audited via the existing OnOutcome sink")
	}
	if err := core.ValidateDecision(dec, true); err != nil {
		t.Errorf("REDIRECT decision failed validation: %v", err)
	}

	// 3.2 — the flow enforcer reuses the EXISTING TargetedEnforcer, acting on flow_id.
	fe := &fakeFlowEnforcer{}
	if !core.CanEnforce(fe, dec) {
		t.Fatal("flow enforcer does not advertise the REDIRECT verdict")
	}
	if err := fe.EnforceTarget(context.Background(), dec, ev.GetNetwork().GetFlowId()); err != nil {
		t.Fatal(err)
	}
	if fe.flowID != "flow-1" {
		t.Errorf("flow enforcer acted on target %q, want the flow_id 'flow-1'", fe.flowID)
	}
}

// 3.3 — NetworkSubject carries METADATA only, never the body (D10/D29); REDIRECT
// validates and no drop/reset verdict was added (mode, not verdict, D14).
func TestNetworkContractBoundaries(t *testing.T) {
	fields := (&corev1.NetworkSubject{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		if strings.Contains(name, "body") || strings.Contains(name, "content") || name == "payload" {
			t.Errorf("NetworkSubject exposes %q — the body must stay in the classifying process (D10/D29)", name)
		}
	}

	dec := &corev1.Decision{
		DecisionId: "d", EventId: "e", Action: corev1.Action_ACTION_REDIRECT,
		Confidence: 0.5, Reason: "r", PolicyId: "p", PolicyVersion: "1",
	}
	if err := core.ValidateDecision(dec, true); err != nil {
		t.Errorf("REDIRECT is not accepted by the closed action set: %v", err)
	}
	for _, n := range corev1.Action_name {
		up := strings.ToUpper(n)
		if strings.Contains(up, "DROP") || strings.Contains(up, "RESET") {
			t.Errorf("action %q exists — reset/drop must be an enforcement MODE, not a verdict (D14)", n)
		}
	}
}
