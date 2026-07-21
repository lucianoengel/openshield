package core_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
)

// A witness reconstructed from a SAVED private key produces anchors verifiable
// under the corresponding public key — so anchoring can run under a stable,
// externally-held key (T-019).
func TestWitnessFromKeyRoundTrips(t *testing.T) {
	orig, err := core.NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	saved := orig.PrivateKey()

	reloaded, err := core.WitnessFromKey(saved)
	if err != nil {
		t.Fatal(err)
	}
	// The reloaded witness has the same public identity.
	if !reloaded.PublicKey().Equal(orig.PublicKey()) {
		t.Fatal("reloaded witness public key differs from the original")
	}
	// An anchor it signs verifies under that public key.
	a := reloaded.Anchor(7, []byte("head-hash"))
	if !core.VerifyAnchor(a, orig.PublicKey()) {
		t.Fatal("anchor from a reloaded witness did not verify under the saved public key")
	}
	// A wrong-length key is rejected.
	if _, err := core.WitnessFromKey([]byte("short")); err == nil {
		t.Error("a wrong-length witness key was accepted")
	}
}
