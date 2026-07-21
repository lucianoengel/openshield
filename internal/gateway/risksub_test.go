package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// signRisk mints a control-plane-signed risk update the way PublishRisk does.
func signRisk(t *testing.T, priv ed25519.PrivateKey, subject string, score float64) []byte {
	t.Helper()
	payload, _ := proto.Marshal(&corev1.RiskUpdate{Subject: subject, RiskScore: score})
	data, err := gateway.SignUpdate(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// SEC-1: a VALIDLY-SIGNED risk update is applied; an unsigned, tampered, or wrong-key
// update is REJECTED and COUNTED — so a publisher who can reach the risk subject (any
// enrolled agent, or anyone past broker mTLS) cannot forge risk for any subject.
func TestRiskSubscriberVerifies(t *testing.T) {
	cpPub, cpPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	store := gateway.NewRiskStore()
	sub := gateway.NewRiskSubscriber(store, cpPub)

	// Valid, control-plane-signed → applied.
	if err := sub.Apply(signRisk(t, cpPriv, "sub_alice", 0.9)); err != nil {
		t.Fatalf("a validly-signed risk update was rejected: %v", err)
	}
	if s, ok := store.Get("sub_alice"); !ok || s != 0.9 {
		t.Errorf("store = %v/%v, want 0.9/true", s, ok)
	}

	// Every forgery is rejected AND leaves the store unchanged.
	forgeries := map[string][]byte{
		"wrong key": signRisk(t, otherPriv, "sub_alice", 0.0), // attacker tries risk=0
		"unsigned (raw RiskUpdate, not a SignedUpdate)": mustMarshal(t, &corev1.RiskUpdate{Subject: "sub_alice", RiskScore: 0.0}),
		"empty signature": func() []byte {
			payload, _ := proto.Marshal(&corev1.RiskUpdate{Subject: "sub_alice", RiskScore: 0.0})
			b, _ := proto.Marshal(&corev1.SignedUpdate{Payload: payload})
			return b
		}(),
		"tampered payload": func() []byte {
			b := signRisk(t, cpPriv, "sub_alice", 0.9)
			b[len(b)-1] ^= 0xff
			return b
		}(),
		"garbage": []byte("not a proto \xff\xff"),
	}
	for name, data := range forgeries {
		if err := sub.Apply(data); err == nil {
			t.Errorf("forgery %q was ACCEPTED — the risk channel must reject unsigned/forged updates", name)
		}
	}
	// The legitimate 0.9 still stands — no forgery overwrote it with risk=0.
	if s, _ := store.Get("sub_alice"); s != 0.9 {
		t.Errorf("a forgery changed the store to %v — verification failed", s)
	}
}

// An empty-subject update, even validly signed, is refused (never a silent no-op).
func TestRiskSubscriberRejectsEmptySubject(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := gateway.NewRiskStore()
	sub := gateway.NewRiskSubscriber(store, pub)
	if err := sub.Apply(signRisk(t, priv, "", 0.9)); err == nil {
		t.Error("a signed risk update with no subject was accepted")
	}
}

// A misconfigured (wrong-length) trusted key must yield an ERROR, not a panic — ed25519.Verify
// panics on a bad-size key, so the length guard prevents a crash-DoS on misconfiguration.
func TestRiskSubscriberBadKeyDoesNotPanic(t *testing.T) {
	store := gateway.NewRiskStore()
	sub := gateway.NewRiskSubscriber(store, ed25519.PublicKey([]byte("too-short")))
	// A WELL-FORMED signed envelope so verification reaches ed25519.Verify — which panics
	// on a bad-size key unless the length guard returns an error first.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := signRisk(t, priv, "sub_x", 0.9)
	if err := sub.Apply(env); err == nil {
		t.Error("a wrong-length trusted key did not error")
	}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
