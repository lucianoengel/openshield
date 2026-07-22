package posture_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
)

// HON-4: a posture update BUILT by the producer is accepted by the gateway's SIGNED posture
// subscriber (SEC-1) and applied to the store — the posture happy-path, previously only its
// reject path could be tested (no producer existed). A wrong-key update is rejected.
func TestProducerRoundTripsThroughSignedSubscriber(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	store := gateway.NewPostureStore()
	// SEC-12: the subscriber verifies each update against the reporting agent's ENROLLED key,
	// resolved by subject. Enrolling pub for every subject lets the happy path verify (signed with
	// priv) while the wrong-key forgery below (signed with otherPriv) still fails verification.
	keyFor := func(_ string) (ed25519.PublicKey, bool) { return pub, true }
	sub := gateway.NewPostureSubscriber(store, keyFor)

	// The producer builds a signed posture update for its own subject.
	r := posture.Report{Compliant: true, DiskEncrypted: true, AgentPresent: true, OSPatchTier: core.PatchCurrent}
	data, err := posture.Build("sub_agent", r, priv)
	if err != nil {
		t.Fatal(err)
	}

	// The gateway verifies + applies it — the tamper-lockout now has real data.
	if err := sub.Apply(data); err != nil {
		t.Fatalf("the producer's signed posture was rejected: %v", err)
	}
	dp, ok := store.Get("sub_agent")
	if !ok || !dp.HasPosture || !dp.Compliant || !dp.DiskEncrypted {
		t.Errorf("store = %+v/%v, want present + compliant + disk-encrypted", dp, ok)
	}

	// A posture update signed with the WRONG key is rejected (a forger cannot inject posture).
	forged, _ := posture.Build("sub_attacker", posture.Report{Compliant: true}, otherPriv)
	if err := sub.Apply(forged); err == nil {
		t.Error("a wrong-key posture update was accepted — SEC-1 verification bypassed")
	}
	if _, ok := store.Get("sub_attacker"); ok {
		t.Error("a forged posture reached the store")
	}
}

// Build refuses an empty subject (a posture update must name the subject it reports for).
func TestBuildRejectsEmptySubject(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := posture.Build("", posture.Report{}, priv); err == nil {
		t.Error("Build accepted an empty subject")
	}
}

// Detect is honest: it never asserts a compliance it did not observe. AgentPresent is true
// (we are running), and Compliant is not true without disk-encryption evidence.
func TestDetectIsHonest(t *testing.T) {
	r := posture.Detect()
	if !r.AgentPresent {
		t.Error("Detect: AgentPresent should be true — the agent is running to report this")
	}
	// Compliant is derived from disk encryption; without that evidence it must not be true.
	if r.Compliant != r.DiskEncrypted {
		t.Errorf("Detect: Compliant=%v but DiskEncrypted=%v — compliance must not exceed the evidence", r.Compliant, r.DiskEncrypted)
	}
	if r.OSPatchTier != core.PatchUnknown {
		t.Errorf("Detect: OSPatchTier=%v, want Unknown (no patch feed to verify currency)", r.OSPatchTier)
	}
}
