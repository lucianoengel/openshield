package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A peer-aware policy escalates on a high peer risk score even with NO PII hit —
// and the whole chain (analyzer → resolver → dispatcher hook → policy) flows a
// Context to the Decision. This is peer-UEBA end to end (D26).
func TestPeerRiskEscalates(t *testing.T) {
	// A policy that alerts on high peer risk alone.
	mod := `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"anomalous peer activity","confidence":0.8} if {
	input.context.has_risk_score
	input.context.risk_score >= 0.7
}`
	pol, err := policy.New(context.Background(), "peer", "1", mod)
	if err != nil {
		t.Fatal(err)
	}

	// Build a population with an outlier via the analyzer.
	a := peerueba.New()
	for _, s := range []string{"s1", "s2", "s3"} {
		for i := 0; i < 5; i++ {
			a.Observe(s)
		}
	}
	for i := 0; i < 100; i++ {
		a.Observe("outlier")
	}

	var reg core.Registry
	reg.Register(pol)
	disp := core.NewDispatcher(&reg, time.Second)
	disp.ResolveContext = a.Resolver() // the ONE core hook

	// The outlier subject, NO classification (no PII hit).
	dec, err := disp.Dispatch(context.Background(), &corev1.Event{
		EventId: "e1", Purpose: corev1.Purpose_PURPOSE_DLP,
		Subject: &corev1.Subject{PseudonymousId: "outlier"},
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("action = %v, want ALERT — a high peer risk should escalate with no PII hit", dec.GetAction())
	}

	// A typical subject does NOT escalate (low peer risk → no matching rule →
	// the reasoned ALLOW).
	dec2, err := disp.Dispatch(context.Background(), &corev1.Event{
		EventId: "e2", Purpose: corev1.Purpose_PURPOSE_DLP,
		Subject: &corev1.Subject{PseudonymousId: "s1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec2.GetAction() == corev1.Action_ACTION_ALERT {
		t.Error("a typical subject escalated — peer risk is not discriminating")
	}
}
