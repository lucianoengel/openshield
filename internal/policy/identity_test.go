package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// The Zero-Trust identity context contract (D85): an identity-aware policy decides
// on identity/role/device-posture — allowing a compliant authorized device and
// DENYING an untrusted (no-posture) or non-compliant one — through the UNCHANGED
// core.Dispatcher, via the ResolveContext seam (the same one peer-UEBA uses, D53).
// This proves the pipeline can REPRESENT and DECIDE on identity before the identity
// PRODUCER exists (proposal §5.2), D69-style contract-first.
func TestIdentityAwareAuthorization(t *testing.T) {
	// A ZT access policy: deny an untrusted device (no posture), deny a
	// non-compliant one, allow a compliant finance device.
	mod := `package openshield
import rego.v1

# Absent posture = untrusted/unattested device (a killed or tampered endpoint) →
# fail CLOSED. This is the tamper-lockout.
decision := {"action":"BLOCK","reason":"device posture unknown","confidence":0.9} if {
	not input.context.device_posture.has_posture
}

# Present but not compliant → deny.
decision := {"action":"BLOCK","reason":"device not compliant","confidence":0.9} if {
	input.context.device_posture.has_posture
	not input.context.device_posture.compliant
}

# Compliant device, authorized role → allow.
decision := {"action":"ALLOW","reason":"compliant finance access","confidence":0.9} if {
	input.context.device_posture.has_posture
	input.context.device_posture.compliant
	input.context.role == "finance"
}`
	pol, err := policy.New(context.Background(), "zt", "1", mod)
	if err != nil {
		t.Fatal(err)
	}

	decide := func(t *testing.T, c *core.Context) *corev1.Decision {
		t.Helper()
		var reg core.Registry
		reg.Register(pol)
		disp := core.NewDispatcher(&reg, time.Second)
		disp.ResolveContext = func(*corev1.Event) *core.Context { return c }
		dec, err := disp.Dispatch(context.Background(), &corev1.Event{
			EventId: "e", Purpose: corev1.Purpose_PURPOSE_DLP,
			Subject: &corev1.Subject{PseudonymousId: "sub_alice"},
		})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return dec
	}

	// Compliant finance device → ALLOW.
	if got := decide(t, &core.Context{
		Identity: "sub_alice", Role: "finance",
		DevicePosture: core.DevicePosture{HasPosture: true, Compliant: true, DiskEncrypted: true},
	}); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("compliant finance device = %v, want ALLOW", got.GetAction())
	}

	// No posture (a killed/tampered endpoint) → BLOCK via the ABSENT-POSTURE rule
	// (the tamper-lockout). The REASON discriminates it from the non-compliant path,
	// so masking has_posture as present is caught here — not just the action.
	if got := decide(t, &core.Context{
		Identity: "sub_alice", Role: "finance",
		DevicePosture: core.DevicePosture{HasPosture: false},
	}); got.GetAction() != corev1.Action_ACTION_BLOCK || got.GetReason() != "device posture unknown" {
		t.Errorf("no-posture device = %v/%q, want BLOCK/\"device posture unknown\" — absent posture must fail CLOSED via the absent rule (D85)",
			got.GetAction(), got.GetReason())
	}

	// Present but non-compliant → BLOCK, via the distinct non-compliant rule.
	if got := decide(t, &core.Context{
		Identity: "sub_alice", Role: "finance",
		DevicePosture: core.DevicePosture{HasPosture: true, Compliant: false},
	}); got.GetAction() != corev1.Action_ACTION_BLOCK || got.GetReason() != "device not compliant" {
		t.Errorf("non-compliant device = %v/%q, want BLOCK/\"device not compliant\"", got.GetAction(), got.GetReason())
	}
}
