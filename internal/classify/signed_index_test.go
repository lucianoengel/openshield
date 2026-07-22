package classify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// reSign re-marshals a SignedIndex from parts, so a test can craft tampered/wrong-kind envelopes.
func reSign(t *testing.T, kind string, index, sig []byte) []byte {
	t.Helper()
	b, err := proto.Marshal(&corev1.SignedIndex{Kind: kind, Index: index, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildSignedEDM builds a tiny real EDM index over one seeded value, signs it, and returns the
// signed bytes + the value (so a test can assert the round-tripped index detects it).
func buildSignedEDM(t *testing.T, priv ed25519.PrivateKey) ([]byte, string) {
	t.Helper()
	const secret = "4111111111111111" // a seeded sensitive value
	idx := classify.NewEDMIndex(0.001, 4)
	idx.Add(secret)
	signed, err := classify.SignIndex(classify.IndexKindEDM, idx.Marshal(), priv)
	if err != nil {
		t.Fatalf("SignIndex: %v", err)
	}
	return signed, secret
}

// TestSignedIndexRoundTrip (DLP-3/ADR-9): a correctly signed index verifies against the operator's
// public key and yields loadable bytes whose index still detects the operator's seeded value.
func TestSignedIndexRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, secret := buildSignedEDM(t, priv)

	got, err := classify.VerifyIndex(signed, pub, classify.IndexKindEDM)
	if err != nil {
		t.Fatalf("VerifyIndex rejected a correctly signed index: %v", err)
	}
	idx, err := classify.LoadEDMIndex(got)
	if err != nil {
		t.Fatalf("verified bytes did not load: %v", err)
	}
	if !idx.Contains(secret) {
		t.Fatal("the round-tripped EDM index does not detect its seeded value")
	}
}

// TestVerifyIndexFailsClosed (DLP-3/ADR-9): a tampered payload, a tampered signature, a wrong key,
// an unsigned/malformed blob, and a wrong kind are ALL rejected with no bytes returned.
func TestVerifyIndexFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := buildSignedEDM(t, priv)

	var env corev1.SignedIndex
	if err := proto.Unmarshal(signed, &env); err != nil {
		t.Fatalf("unmarshal signed index: %v", err)
	}
	// Tampered signature (flip a bit of the SignedIndex.signature).
	tsig := append([]byte(nil), env.GetSignature()...)
	tsig[len(tsig)-1] ^= 0x01
	tamperedSig := reSign(t, env.GetKind(), env.GetIndex(), tsig)

	// Tampered payload (flip a byte of the index).
	tidx := append([]byte(nil), env.GetIndex()...)
	tidx[0] ^= 0x01
	tamperedPayload := reSign(t, env.GetKind(), tidx, env.GetSignature())

	// Wrong kind in the envelope (re-marshal as idm; the signature was over kind=edm).
	wrongKindEnvelope := reSign(t, classify.IndexKindIDM, env.GetIndex(), env.GetSignature())

	cases := []struct {
		name     string
		signed   []byte
		pub      ed25519.PublicKey
		wantKind string
	}{
		{"tampered signature", tamperedSig, pub, classify.IndexKindEDM},
		{"tampered payload", tamperedPayload, pub, classify.IndexKindEDM},
		{"wrong key", signed, otherPub, classify.IndexKindEDM},
		{"malformed blob", []byte("not a signed index"), pub, classify.IndexKindEDM},
		{"wrong requested kind", signed, pub, classify.IndexKindIDM},
		{"kind mismatch in envelope", wrongKindEnvelope, pub, classify.IndexKindIDM},
	}
	for _, c := range cases {
		got, err := classify.VerifyIndex(c.signed, c.pub, c.wantKind)
		if err == nil || got != nil {
			t.Errorf("%s: VerifyIndex accepted an invalid index (got %d bytes, err %v)", c.name, len(got), err)
		}
	}
	// The valid index still verifies (sanity: the failures above are the tamper, not a broken helper).
	if _, err := classify.VerifyIndex(signed, pub, classify.IndexKindEDM); err != nil {
		t.Fatalf("the untampered index failed to verify: %v", err)
	}
}

// TestSignedIndexDomainSeparation (DLP-3/ADR-9): a signature is bound to its DLP-index domain, so a
// signed rules bundle is never accepted as an index (and the index kinds do not cross). This is what
// stops a signature minted for one purpose (or one kind) validating for another.
func TestSignedIndexDomainSeparation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// A signed RULES bundle (a different protocol under the same key) must not verify as an index.
	rulesBundle, err := classify.SignRuleBundle(&corev1.RuleBundle{}, priv)
	if err != nil {
		t.Fatalf("SignRuleBundle: %v", err)
	}
	if got, err := classify.VerifyIndex(rulesBundle, pub, classify.IndexKindEDM); err == nil || got != nil {
		t.Error("a signed rules bundle was accepted as a DLP index — domain separation broken")
	}

	// An index signed as one kind must not verify as another (the signature covers the kind).
	idx := classify.NewEDMIndex(0.001, 2)
	idx.Add("x")
	edmSigned, _ := classify.SignIndex(classify.IndexKindEDM, idx.Marshal(), priv)
	if got, err := classify.VerifyIndex(edmSigned, pub, classify.IndexKindRecord); err == nil || got != nil {
		t.Error("an EDM-signed index was accepted as a record index — kind not bound into the signature")
	}
}
