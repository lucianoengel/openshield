package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A Zero-Trust access policy can require a HARDWARE-ATTESTED device (ZT-1): the
// attested signal (set only by the gateway's own quote verification) is exposed at
// input.context.device_posture.attested, and a policy that requires it allows an
// attested device and denies an otherwise-identical unattested one — through the
// UNCHANGED core.Dispatcher via the ResolveContext seam.
func TestAttestationAwareAuthorization(t *testing.T) {
	mod := `package openshield
import rego.v1

# A hardware-attested device is admitted.
decision := {"action":"ALLOW","reason":"attested device","confidence":0.9} if {
	input.context.device_posture.attested
}

# Anything not attested is denied (fail closed — the point of requiring attestation).
decision := {"action":"BLOCK","reason":"device not hardware-attested","confidence":0.9} if {
	not input.context.device_posture.attested
}`
	pol, err := policy.New(context.Background(), "zt-attest", "1", mod)
	if err != nil {
		t.Fatal(err)
	}

	decide := func(t *testing.T, c *core.Context) string {
		t.Helper()
		var reg core.Registry
		reg.Register(pol)
		disp := core.NewDispatcher(&reg, time.Second)
		disp.ResolveContext = func(*corev1.Event) *core.Context { return c }
		dec, err := disp.Dispatch(context.Background(), &corev1.Event{
			EventId: "e", Purpose: corev1.Purpose_PURPOSE_DLP,
			Subject: &corev1.Subject{PseudonymousId: "sub_device"},
		})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return dec.GetAction().String()
	}

	attested := &core.Context{DevicePosture: core.DevicePosture{HasPosture: true, Attested: true}}
	if got := decide(t, attested); got != "ACTION_ALLOW" {
		t.Fatalf("attested device: want ACTION_ALLOW, got %s", got)
	}

	unattested := &core.Context{DevicePosture: core.DevicePosture{HasPosture: true, Attested: false}}
	if got := decide(t, unattested); got != "ACTION_BLOCK" {
		t.Fatalf("unattested device: want ACTION_BLOCK, got %s", got)
	}
}
