package fim

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
)

// Operator-signed FIM baseline (HIPS-4 increment 3).
//
// The baseline manifest records the known-good hashes FIM compares against. As a plain file, whoever
// can write it controls the "known-good" state: an attacker who rewrites it to match their tampered
// files hides all drift. This mirrors the DLP signed-index model (ADR-9/D100): an operator signs the
// baseline with an operator key OFFLINE, and a node loads it ONLY after the signature verifies against
// a trusted operator PUBLIC key. The node never holds the signing key, so a compromised node cannot
// forge a baseline, and a compromised distribution path can copy a signed baseline but cannot alter it.

// fimSigDomain domain-separates a FIM baseline signature from every other Ed25519 signature in the
// system (DLP index, signed rules, ledger, risk/posture), so a signature minted for the baseline can
// never validate for another purpose and vice-versa. The 0x1f unit separator cannot appear in the tag.
const fimSigDomain = "openshield-fim-baseline\x1f"

// signedManifest is the on-disk envelope: the manifest bytes VERBATIM (so verification re-checks the
// exact bytes that were signed — no re-marshal drift) plus the detached signature.
type signedManifest struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature []byte          `json:"signature"`
}

// signingBytes is the exact byte string signed and verified: the domain tag followed by the manifest
// bytes. Recomputed identically on both sides.
func signingBytes(manifest []byte) []byte {
	out := make([]byte, 0, len(fimSigDomain)+len(manifest))
	out = append(out, fimSigDomain...)
	out = append(out, manifest...)
	return out
}

// SignManifest signs a baseline with an operator private key, producing the bytes VerifyManifest checks
// (the operator-authoring side, openshield-fim-baseline). It stores the manifest bytes verbatim in the
// envelope so verification checks exactly what was signed.
func SignManifest(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("fim: signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	if m == nil || len(m.Entries) == 0 {
		return nil, fmt.Errorf("fim: refusing to sign an empty baseline")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signingBytes(raw))
	return json.Marshal(signedManifest{Manifest: raw, Signature: sig})
}

// VerifyManifest verifies a signed baseline against a trusted operator public key and returns the inner
// manifest. Fail-closed: a malformed envelope, a missing/invalid signature, a wrong or wrong-size key
// returns an error and NO manifest. Verification happens BEFORE the manifest is parsed for use.
func VerifyManifest(signed []byte, trustedPub ed25519.PublicKey) (*Manifest, error) {
	if len(trustedPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fim: trusted key must be %d bytes", ed25519.PublicKeySize)
	}
	var env signedManifest
	if err := json.Unmarshal(signed, &env); err != nil {
		return nil, fmt.Errorf("fim: malformed signed baseline: %w", err)
	}
	if len(env.Signature) == 0 {
		return nil, fmt.Errorf("fim: baseline is unsigned")
	}
	if len(env.Manifest) == 0 {
		return nil, fmt.Errorf("fim: signed envelope carries no manifest")
	}
	if !ed25519.Verify(trustedPub, signingBytes(env.Manifest), env.Signature) {
		return nil, fmt.Errorf("fim: signature does not verify against the trusted operator key")
	}
	var m Manifest
	if err := json.Unmarshal(env.Manifest, &m); err != nil {
		return nil, fmt.Errorf("fim: verified envelope has a malformed manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return &m, nil
}

// LoadSignedManifest reads a signed baseline from disk and verifies it.
func LoadSignedManifest(path string, trustedPub ed25519.PublicKey) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return VerifyManifest(b, trustedPub)
}
