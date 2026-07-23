package fim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func baselineFor(t *testing.T) *Manifest {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "critical.conf")
	if err := os.WriteFile(f, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, _, err := BuildBaseline([]string{f}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	m := baselineFor(t)
	pub, priv := keypair(t)
	signed, err := SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyManifest(signed, pub)
	if err != nil {
		t.Fatalf("verify a validly-signed baseline: %v", err)
	}
	if len(got.Entries) != len(m.Entries) {
		t.Fatalf("verified manifest has %d entries, want %d", len(got.Entries), len(m.Entries))
	}
	for p, e := range m.Entries {
		if got.Entries[p].SHA256 != e.SHA256 || got.Entries[p].SHA256 == "" {
			t.Fatalf("hash for %s did not round-trip", p)
		}
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	m := baselineFor(t)
	pub, priv := keypair(t)
	signed, _ := SignManifest(m, priv)

	// Alter the manifest region: unmarshal the envelope, flip a hash char, re-marshal the envelope
	// (keeping the original signature) — the signature no longer matches the altered manifest.
	var env signedManifest
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	env.Manifest = bytes.Replace(env.Manifest, []byte(`"sha256":"`), []byte(`"sha256":"0`), 1)
	tampered, _ := json.Marshal(env)

	if _, err := VerifyManifest(tampered, pub); err == nil {
		t.Fatal("a tampered signed baseline verified — the signature must reject an altered manifest")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	m := baselineFor(t)
	_, priv := keypair(t)
	other, _ := keypair(t) // a DIFFERENT public key
	signed, _ := SignManifest(m, priv)

	if _, err := VerifyManifest(signed, other); err == nil {
		t.Fatal("a baseline verified under the wrong key")
	}
}

func TestVerifyRejectsUnsignedAndMalformed(t *testing.T) {
	pub, _ := keypair(t)
	m := baselineFor(t)

	// A plain (unsigned) manifest is not a signed envelope.
	plain, _ := json.Marshal(m)
	if _, err := VerifyManifest(plain, pub); err == nil {
		t.Error("a plain unsigned manifest verified as signed")
	}
	// Garbage / empty.
	if _, err := VerifyManifest([]byte("{}"), pub); err == nil {
		t.Error("an envelope with no signature verified")
	}
	if _, err := VerifyManifest([]byte("not json"), pub); err == nil {
		t.Error("garbage verified")
	}
}

// A signature over the RAW manifest (without the domain tag) must NOT verify with the domain-tagged
// verifier — domain separation prevents a signature minted for another purpose from validating here.
func TestDomainSeparation(t *testing.T) {
	m := baselineFor(t)
	pub, priv := keypair(t)
	raw, _ := json.Marshal(m)
	rawSig := ed25519.Sign(priv, raw) // signed WITHOUT the domain tag
	env, _ := json.Marshal(signedManifest{Manifest: raw, Signature: rawSig})
	if _, err := VerifyManifest(env, pub); err == nil {
		t.Fatal("a signature over the un-domained bytes verified — domain separation is not enforced")
	}
}
