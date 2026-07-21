package usb_test

import (
	"context"
	"testing"
	"time"

	usbconn "github.com/lucianoengel/openshield/internal/connectors/usb"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	usbenf "github.com/lucianoengel/openshield/internal/enforcers/usb"
	"github.com/lucianoengel/openshield/internal/policy"
)

// End to end through the REAL pipeline: a USB event produced by the connector is
// dispatched through the shipped default policy to a Decision, and that Decision
// alone drives the enforcer. This exercises the CrowdSec separation (D14) with a
// real event, a real policy Decision and a real enforcer — stronger than
// asserting the interface shape.
func TestUSBEventToEnforcement(t *testing.T) {
	// Producer → USB event (serial pseudonymised at the source).
	prod := usbconn.NewProducer("agent-1", []byte("k"))
	event := prod.Event(usbconn.Device{VendorID: "1d6b", ProductID: "0002", Serial: "SN-1"}, 0)

	// Real default policy in the pipeline.
	pol, err := policy.NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reg core.Registry
	reg.Register(pol)
	disp := core.NewDispatcher(&reg, time.Second)

	dec, err := disp.Dispatch(context.Background(), event)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// A USB event has no classification, so the default policy allows it with a
	// reason — a real Decision from the real policy (observe-only, D1).
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("decision action = %v, want ALLOW for a USB event under the default policy", dec.GetAction())
	}

	// The enforcer acts on the Decision ALONE.
	f := &fakeAuthorizer{}
	e := usbenf.New(f)
	if !core.CanEnforce(e, dec) {
		t.Fatal("the USB enforcer cannot carry out the policy's Decision")
	}
	if err := e.Enforce(context.Background(), dec); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0] != true {
		t.Errorf("ALLOW did not set the permissive posture end to end: %v", f.calls)
	}
}
