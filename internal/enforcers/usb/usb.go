// Package usb is a real USB enforcer (T-020) — the first non-stub enforcement
// point, built to prove the Enforcer contract end to end (D1).
//
// It receives ONLY a Decision (D14) and enacts it by setting the kernel's global
// USB authorization posture, `/sys/bus/usb/devices/usbN/authorized_default`:
// deauthorise-new-devices for BLOCK, authorise for ALLOW. This is the standard
// Linux mechanism USBGuard builds on, so the enforcer changes an actual
// enforcement point, not a simulated one.
//
// Scope, stated honestly: this is the GLOBAL posture, not per-device. Per-device
// enforcement would need the Decision to carry a typed enforcement TARGET, which
// it does not — the small core addition D26 predicts a new-shape capability
// needs, deferred until targeted enforcement is actually built.
//
// Phase 1 is observe-only (D1): nothing in the live pipeline invokes this, and
// the default policy never emits BLOCK. The enforcer is real and CAN block; a
// test drives it.
package usb

import (
	"context"
	"fmt"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// USBAuthorizer sets the global USB authorization default. Behind an interface so
// the decision logic is tested without privilege; the sysfs implementation writes
// the real files.
type USBAuthorizer interface {
	// SetDefaultAuthorized(true) permits newly attached devices; (false)
	// deauthorises them by default.
	SetDefaultAuthorized(authorized bool) error
}

// Enforcer implements core.Enforcer for USB.
type Enforcer struct {
	Auth USBAuthorizer
}

// New returns a USB enforcer over the given authorizer.
func New(a USBAuthorizer) *Enforcer { return &Enforcer{Auth: a} }

// Capabilities reports the postures this enforcer can set. The policy engine asks
// only "can you carry out this Decision" — never how it was reached (D14).
func (e *Enforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_ALLOW, corev1.Action_ACTION_BLOCK}
}

// Enforce enacts a Decision. An action this enforcer does not advertise is an
// ERROR, never a silent no-op: a no-op is an enforcement that did not happen but
// looks like it did — the quiet failure the audit trail exists to prevent.
func (e *Enforcer) Enforce(_ context.Context, d *corev1.Decision) error {
	switch d.GetAction() {
	case corev1.Action_ACTION_BLOCK:
		return e.Auth.SetDefaultAuthorized(false)
	case corev1.Action_ACTION_ALLOW:
		return e.Auth.SetDefaultAuthorized(true)
	default:
		return fmt.Errorf("usb enforcer: cannot carry out action %v (advertises ALLOW, BLOCK only)", d.GetAction())
	}
}

var _ core.Enforcer = (*Enforcer)(nil)
