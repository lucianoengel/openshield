package identity_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/identity"
)

// Each agent's key is its own — never a shared secret. One agent's signature
// does not verify under another's key.
func TestPerAgentKeys(t *testing.T) {
	a, err := identity.Generate("agent-A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Generate("agent-B")
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey().Equal(b.PublicKey()) {
		t.Fatal("two agents generated the same key — that is a shared secret (A6)")
	}

	payload := []byte("telemetry")
	sig := a.Sign(1, payload)
	// Verifies under A's key...
	if !ed25519.Verify(a.PublicKey(), identity.CanonicalEnvelope("agent-A", 1, payload), sig) {
		t.Error("A's signature does not verify under A's key")
	}
	// ...but NOT under B's.
	if ed25519.Verify(b.PublicKey(), identity.CanonicalEnvelope("agent-A", 1, payload), sig) {
		t.Error("A's signature verified under B's key — keys are not per-agent")
	}
}
