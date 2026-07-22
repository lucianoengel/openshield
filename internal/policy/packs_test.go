package policy_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

func stateWithType(dt corev1.DetectorType, conf float64) *core.State {
	return &core.State{
		Event: &corev1.Event{EventId: "e1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED},
		Classification: &corev1.LocalClassification{EventId: "e1",
			Matches: []*corev1.LocalMatch{{DetectorType: dt, Confidence: conf}}},
	}
}

// DLP-5: each compliance pack ALERTs on a detector in its regulatory scope and ALLOWs an unrelated
// detector — the packs make the classifier's breadth usable as PCI/HIPAA/GDPR controls.
func TestCompliancePacks(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		pack       string
		inScope    corev1.DetectorType // must ALERT
		outOfScope corev1.DetectorType // must ALLOW
	}{
		{"pci", corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA},
		{"pci", corev1.DetectorType_DETECTOR_TYPE_ABA_ROUTING, corev1.DetectorType_DETECTOR_TYPE_EMAIL},
		{"hipaa", corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA, corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD},
		{"hipaa", corev1.DetectorType_DETECTOR_TYPE_NPI, corev1.DetectorType_DETECTOR_TYPE_EMAIL},
		{"gdpr", corev1.DetectorType_DETECTOR_TYPE_EMAIL, corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD},
		{"gdpr", corev1.DetectorType_DETECTOR_TYPE_CA_SIN, corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA},
	}
	for _, c := range cases {
		stage, err := policy.NewPack(ctx, c.pack)
		if err != nil {
			t.Fatalf("load pack %q: %v", c.pack, err)
		}
		if d := decide(t, stage, stateWithType(c.inScope, 0.9)); d.GetAction() != corev1.Action_ACTION_ALERT {
			t.Errorf("%s on %v = %v, want ALERT (in scope)", c.pack, c.inScope, d.GetAction())
		}
		if d := decide(t, stage, stateWithType(c.outOfScope, 0.9)); d.GetAction() != corev1.Action_ACTION_ALLOW {
			t.Errorf("%s on %v = %v, want ALLOW (out of scope)", c.pack, c.outOfScope, d.GetAction())
		}
	}

	// An unknown pack is an error, never a silent permissive fallback.
	if _, err := policy.NewPack(ctx, "sox"); err == nil {
		t.Error("unknown compliance pack was accepted")
	}
	if len(policy.Packs()) != 3 {
		t.Errorf("Packs() = %v, want 3 (pci/hipaa/gdpr)", policy.Packs())
	}
}
