package gateway_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// A published RiskUpdate decodes into the RiskStore (D91) — the round-trip a server
// PublishRisk and a gateway subscription perform.
func TestApplyRiskUpdate(t *testing.T) {
	store := gateway.NewRiskStore()
	data, err := proto.Marshal(&corev1.RiskUpdate{Subject: "sub_alice", RiskScore: 0.9})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ApplyRiskUpdate(data, store); err != nil {
		t.Fatal(err)
	}
	if s, ok := store.Get("sub_alice"); !ok || s != 0.9 {
		t.Errorf("store after apply = %v/%v, want 0.9/true", s, ok)
	}
}

// A malformed payload errors and sets nothing (never a silent no-op).
func TestApplyRiskUpdateRejectsMalformed(t *testing.T) {
	store := gateway.NewRiskStore()
	if err := gateway.ApplyRiskUpdate([]byte("not a proto \xff\xff"), store); err == nil {
		t.Error("a malformed risk update was accepted")
	}
	// An empty-subject update is also refused.
	data, _ := proto.Marshal(&corev1.RiskUpdate{Subject: "", RiskScore: 0.9})
	if err := gateway.ApplyRiskUpdate(data, store); err == nil {
		t.Error("a risk update with no subject was accepted")
	}
}
