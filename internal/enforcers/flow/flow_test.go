package flow_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/flow"
)

type fakeTable struct{ blocked, redirected []string }

func (t *fakeTable) Block(f string) error    { t.blocked = append(t.blocked, f); return nil }
func (t *fakeTable) Redirect(f string) error { t.redirected = append(t.redirected, f); return nil }

func dec(a corev1.Action) *corev1.Decision {
	return &corev1.Decision{DecisionId: "d", EventId: "e", Action: a}
}

// The enforcer advertises exactly the network verdicts — CanEnforce gates the
// dispatch on them.
func TestCapabilitiesAreTheNetworkVerdicts(t *testing.T) {
	e := flow.New(&fakeTable{})
	if !core.CanEnforce(e, dec(corev1.Action_ACTION_BLOCK)) {
		t.Error("flow enforcer should advertise BLOCK")
	}
	if !core.CanEnforce(e, dec(corev1.Action_ACTION_REDIRECT)) {
		t.Error("flow enforcer should advertise REDIRECT")
	}
	if core.CanEnforce(e, dec(corev1.Action_ACTION_ALERT)) {
		t.Error("flow enforcer must NOT advertise ALERT — it carries flow verdicts only")
	}
}

// EnforceTarget routes BLOCK/REDIRECT to the table by flow_id.
func TestEnforceTargetRoutesByAction(t *testing.T) {
	tbl := &fakeTable{}
	e := flow.New(tbl)
	if err := e.EnforceTarget(context.Background(), dec(corev1.Action_ACTION_BLOCK), "f1"); err != nil {
		t.Fatal(err)
	}
	if err := e.EnforceTarget(context.Background(), dec(corev1.Action_ACTION_REDIRECT), "f2"); err != nil {
		t.Fatal(err)
	}
	if len(tbl.blocked) != 1 || tbl.blocked[0] != "f1" {
		t.Errorf("blocked = %v, want [f1]", tbl.blocked)
	}
	if len(tbl.redirected) != 1 || tbl.redirected[0] != "f2" {
		t.Errorf("redirected = %v, want [f2]", tbl.redirected)
	}
}

// An action the enforcer does not advertise is refused, not guessed (D14).
func TestEnforceTargetRejectsUnadvertisedAction(t *testing.T) {
	tbl := &fakeTable{}
	e := flow.New(tbl)
	if err := e.EnforceTarget(context.Background(), dec(corev1.Action_ACTION_ALERT), "f1"); err == nil {
		t.Fatal("ALERT reached the flow enforcer and was not refused")
	}
	if len(tbl.blocked)+len(tbl.redirected) != 0 {
		t.Error("the table was touched for an unadvertised action")
	}
}

// A flow verdict with no flow_id cannot act — refused rather than acting on an
// empty target.
func TestEmptyTargetIsRefused(t *testing.T) {
	e := flow.New(&fakeTable{})
	if err := e.EnforceTarget(context.Background(), dec(corev1.Action_ACTION_BLOCK), ""); err == nil {
		t.Fatal("an empty flow_id target was accepted")
	}
}

// Enforce without a target is a misuse — the gateway always calls EnforceTarget.
func TestEnforceWithoutTargetIsRefused(t *testing.T) {
	e := flow.New(&fakeTable{})
	if err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_BLOCK)); err == nil {
		t.Fatal("Enforce without a flow_id target was accepted")
	}
}
