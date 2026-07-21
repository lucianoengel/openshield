package peerueba_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Risk is PEER-RELATIVE and cross-entity: a subject far above its peers scores
// high, a typical one low — the new shape D26 names.
func TestPeerRisk(t *testing.T) {
	a := peerueba.New()
	// A population of typical subjects with ~10 events each, and one outlier.
	for _, s := range []string{"s1", "s2", "s3", "s4"} {
		for i := 0; i < 10; i++ {
			a.Observe(s)
		}
	}
	for i := 0; i < 200; i++ { // outlier: 20x the peers
		a.Observe("outlier")
	}

	out := a.ContextFor("outlier")
	typ := a.ContextFor("s1")
	if out == nil || typ == nil {
		t.Fatal("expected a Context for known subjects in a population with peers")
	}
	if !out.HasRiskScore || !typ.HasRiskScore {
		t.Fatal("HasRiskScore should be set")
	}
	if !(out.RiskScore > typ.RiskScore) {
		t.Errorf("outlier risk %.3f not > typical risk %.3f — risk is not peer-relative", out.RiskScore, typ.RiskScore)
	}
	if out.RiskScore < 0.5 {
		t.Errorf("a 20x-peer outlier scored only %.3f — expected high peer risk", out.RiskScore)
	}
	// A typical subject sits near the mean → low risk.
	if typ.RiskScore > 0.5 {
		t.Errorf("a typical subject scored %.3f — expected low peer risk", typ.RiskScore)
	}

	// The resolver reads the pseudonymous subject.
	res := a.Resolver()
	ev := &corev1.Event{Subject: &corev1.Subject{PseudonymousId: "outlier"}}
	if c := res(ev); c == nil || !(c.RiskScore > 0.5) {
		t.Errorf("resolver did not surface the outlier's peer risk: %+v", c)
	}

	// Too small a population → no peers → nil.
	small := peerueba.New()
	small.Observe("only")
	if small.ContextFor("only") != nil {
		t.Error("a single-subject population has no peers; risk must be nil")
	}
}
