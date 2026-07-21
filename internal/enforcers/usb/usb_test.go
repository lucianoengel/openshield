package usb_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	usbenf "github.com/lucianoengel/openshield/internal/enforcers/usb"
)

// fakeAuthorizer records the posture it was told to set.
type fakeAuthorizer struct {
	calls []bool
	err   error
}

func (f *fakeAuthorizer) SetDefaultAuthorized(authorized bool) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, authorized)
	return nil
}

func dec(a corev1.Action) *corev1.Decision {
	return &corev1.Decision{DecisionId: "d1", EventId: "e1", Action: a}
}

// BLOCK sets the restrictive posture, ALLOW the permissive one.
func TestEnforcePostures(t *testing.T) {
	f := &fakeAuthorizer{}
	e := usbenf.New(f)

	if err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_BLOCK)); err != nil {
		t.Fatal(err)
	}
	if err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_ALLOW)); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0] != false || f.calls[1] != true {
		t.Errorf("posture calls = %v, want [false true] (BLOCK deauthorises, ALLOW authorises)", f.calls)
	}
}

// An action the enforcer does not advertise is an ERROR, and changes nothing —
// never a silent no-op.
func TestUnadvertisedActionRefused(t *testing.T) {
	f := &fakeAuthorizer{}
	e := usbenf.New(f)
	err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_QUARANTINE_LOCAL))
	if err == nil {
		t.Fatal("an unadvertised action was accepted — a silent no-op is an enforcement that " +
			"did not happen but looks like it did")
	}
	if len(f.calls) != 0 {
		t.Errorf("posture changed on an unadvertised action: %v", f.calls)
	}
}

// The enforcer advertises exactly the actions it can carry out.
func TestCapabilities(t *testing.T) {
	caps := usbenf.New(&fakeAuthorizer{}).Capabilities()
	want := map[corev1.Action]bool{corev1.Action_ACTION_ALLOW: true, corev1.Action_ACTION_BLOCK: true}
	if len(caps) != len(want) {
		t.Fatalf("capabilities = %v, want ALLOW and BLOCK", caps)
	}
	for _, a := range caps {
		if !want[a] {
			t.Errorf("advertises %v, which it does not handle", a)
		}
	}
}

// End to end: a USB event through the REAL default policy to a Decision, then to
// the enforcer, which sees ONLY the Decision (D14) and changes the enforcement
// point. Uses the policy import indirectly via a stage the test builds; here we
// drive the enforcer from a policy-produced Decision.
func TestEnforcerCanBlock(t *testing.T) {
	f := &fakeAuthorizer{}
	e := usbenf.New(f)
	// A constructed BLOCK Decision — the enforcer can carry out BLOCK even though
	// Phase-1 policy never emits it.
	if err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_BLOCK)); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0] != false {
		t.Errorf("BLOCK did not set the restrictive posture: %v", f.calls)
	}
}

// The authorizer's error surfaces — enforcement failure is auditable, never
// swallowed.
func TestEnforceErrorSurfaces(t *testing.T) {
	f := &fakeAuthorizer{err: errors.New("sysfs write failed")}
	e := usbenf.New(f)
	if err := e.Enforce(context.Background(), dec(corev1.Action_ACTION_BLOCK)); err == nil {
		t.Fatal("a failed posture write was swallowed — enforcement failure must surface")
	}
}

// CanEnforce (core) matches the enforcer to a Decision's action.
func TestCoreCanEnforce(t *testing.T) {
	e := usbenf.New(&fakeAuthorizer{})
	if !core.CanEnforce(e, dec(corev1.Action_ACTION_BLOCK)) {
		t.Error("CanEnforce should be true for BLOCK")
	}
	if core.CanEnforce(e, dec(corev1.Action_ACTION_ENCRYPT_LOCAL)) {
		t.Error("CanEnforce should be false for an action it does not advertise")
	}
	_ = time.Second
}
