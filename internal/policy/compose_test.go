package policy_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// DLP-5b: composing a compliance pack onto the default MUST NOT disable the default's protections.
// With each pack enabled, a suspicious process (behavioral) STILL alerts, a checksum-backed CPF STILL
// alerts, and the pack's own in-scope detector alerts — all through the real composed Stage.Run. This
// is the exact regression the old replace-the-default wiring hid.
func TestDefaultProtectionsSurviveEveryPack(t *testing.T) {
	ctx := context.Background()
	inScope := map[string]corev1.DetectorType{
		"pci":   corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD,
		"hipaa": corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA,
		"gdpr":  corev1.DetectorType_DETECTOR_TYPE_EMAIL,
	}
	for _, pack := range policy.Packs() {
		stage, err := policy.NewComposite(ctx, []string{pack}, "")
		if err != nil {
			t.Fatalf("compose default+%s: %v", pack, err)
		}
		// Default protection 1: behavioral process alerting (out of every pack's scope).
		if d := decide(t, stage, procState("/bin/bash", "/usr/sbin/nginx", "bash", "-c", "id")); d.GetAction() != corev1.Action_ACTION_ALERT {
			t.Errorf("[%s] suspicious process = %v, want ALERT — behavioral alerting was disabled by the pack", pack, d.GetAction())
		}
		// Default protection 2: the strong-detector (CPF) alert.
		if d := decide(t, stage, stateWithType(corev1.DetectorType_DETECTOR_TYPE_CPF, 0.95)); d.GetAction() != corev1.Action_ACTION_ALERT {
			t.Errorf("[%s] CPF = %v, want ALERT — the strong-detector alert was disabled by the pack", pack, d.GetAction())
		}
		// The pack itself still fires on its own scope.
		if d := decide(t, stage, stateWithType(inScope[pack], 0.9)); d.GetAction() != corev1.Action_ACTION_ALERT {
			t.Errorf("[%s] in-scope %v = %v, want ALERT (the pack did not compose in)", pack, inScope[pack], d.GetAction())
		}
		// The composed bundle identity records the members.
		if b := stage.Bundle(); b != "default+"+pack {
			t.Errorf("[%s] bundle = %q, want %q", pack, b, "default+"+pack)
		}
	}
}

// An operator custom module composes too, and the most-restrictive verb wins across modules: a
// benign file event the default would ALLOW is escalated to BLOCK by a custom rule.
func TestCustomModuleComposesMostRestrictive(t *testing.T) {
	ctx := context.Background()
	blockAll := `package openshield
import rego.v1
decision := {"action": "BLOCK", "reason": "operator override"}`
	stage, err := policy.NewComposite(ctx, nil, blockAll)
	if err != nil {
		t.Fatalf("compose default+custom: %v", err)
	}
	// A clean file event: default → ALLOW, custom → BLOCK ⇒ BLOCK wins (most-restrictive).
	d := decide(t, stage, &core.State{
		Event:          &corev1.Event{EventId: "f1", Purpose: corev1.Purpose_PURPOSE_DLP, Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED},
		Classification: &corev1.LocalClassification{EventId: "f1"},
	})
	if d.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Errorf("default+custom on a clean event = %v, want BLOCK (custom escalation must win)", d.GetAction())
	}
	if d.GetReason() != "operator override" {
		t.Errorf("reason = %q, want the winning module's reason", d.GetReason())
	}
}

// A composite of only the default is behavior-identical to the plain default (composition of one
// member is the identity).
func TestCompositeSingleMemberIsIdentity(t *testing.T) {
	ctx := context.Background()
	comp, err := policy.NewComposite(ctx, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	def := mustDefault(t)
	for _, st := range []struct {
		name  string
		state *core.State
	}{
		{"cpf", stateWithType(corev1.DetectorType_DETECTOR_TYPE_CPF, 0.95)},
		{"benign-proc", procState("/bin/ls", "/bin/bash", "ls", "-l")},
		{"suspicious-proc", procState("/bin/bash", "/usr/sbin/nginx", "bash", "-c", "id")},
	} {
		if got, want := decide(t, comp, st.state).GetAction(), decide(t, def, st.state).GetAction(); got != want {
			t.Errorf("[%s] composite-of-default = %v, default = %v — 1-member composite must be the identity", st.name, got, want)
		}
	}
}
