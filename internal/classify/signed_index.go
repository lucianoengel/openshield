package classify

import (
	"crypto/ed25519"
	"fmt"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Signed, operator-authored DLP detection indexes (DLP-3 / ADR-9).
//
// The EDM/multi-cell/IDM indexes are k-anonymized (hashes only) and ship into the sandboxed
// worker, but nothing bound them to the operator: whoever could write the index file controlled
// what the DLP detector matched — a poisoned index that matches nothing SILENTLY disables exfil
// detection, one that matches everything is a DoS. This mirrors the signed custom-rules model
// (D100): an operator signs the index with an operator key, the node loads it ONLY after the
// signature verifies against a trusted operator public key. A compromised control plane may
// DISTRIBUTE a signed index but cannot FORGE the signature, so it cannot inject or poison the
// detection data (T2/D14).

// Index kinds. The kind is bound into the signature (below), so a signed EDM index cannot be
// loaded into the IDM slot even under the same operator key.
const (
	IndexKindEDM    = "edm"
	IndexKindRecord = "record"
	IndexKindIDM    = "idm"
)

// indexSigDomain domain-separates an index signature from every other Ed25519 signature in the
// system (notably the D100 rules signature), so a signature minted for one purpose can never
// validate for another. The 0x1f unit separator cannot appear in a kind constant.
const indexSigDomain = "openshield-dlp-index\x1f"

// indexSigningBytes is the exact byte string signed and verified: the domain tag, the kind, and
// the index payload, unit-separated. Recomputed identically on both sides.
func indexSigningBytes(kind string, index []byte) []byte {
	out := make([]byte, 0, len(indexSigDomain)+len(kind)+1+len(index))
	out = append(out, indexSigDomain...)
	out = append(out, kind...)
	out = append(out, 0x1f)
	out = append(out, index...)
	return out
}

// SignIndex signs a serialized index (the bytes from EDMIndex/RecordIndex/DocumentIndex.Marshal)
// with an operator private key, producing the bytes VerifyIndex checks. This is the operator-
// authoring side (the openshield-dlp-index tool). kind must be one of the IndexKind* constants.
func SignIndex(kind string, index []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if !validIndexKind(kind) {
		return nil, fmt.Errorf("index: unknown kind %q", kind)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("index: signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	if len(index) == 0 {
		return nil, fmt.Errorf("index: refusing to sign an empty index")
	}
	sig := ed25519.Sign(priv, indexSigningBytes(kind, index))
	return proto.Marshal(&corev1.SignedIndex{Kind: kind, Index: index, Signature: sig})
}

// VerifyIndex verifies a signed index against a trusted operator public key and the EXPECTED kind,
// returning the inner serialized index bytes. It is fail-closed: a malformed envelope, a missing/
// invalid signature, a wrong key, or a kind mismatch returns an error and NO bytes. Verification
// happens BEFORE the inner index is ever parsed, so an unverified index cannot reach a loader.
func VerifyIndex(signed []byte, trustedPub ed25519.PublicKey, wantKind string) ([]byte, error) {
	if len(trustedPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("index: trusted key must be %d bytes", ed25519.PublicKeySize)
	}
	if !validIndexKind(wantKind) {
		return nil, fmt.Errorf("index: unknown expected kind %q", wantKind)
	}
	var si corev1.SignedIndex
	if err := proto.Unmarshal(signed, &si); err != nil {
		return nil, fmt.Errorf("index: malformed signed index: %w", err)
	}
	if len(si.GetSignature()) == 0 {
		return nil, fmt.Errorf("index: index is unsigned")
	}
	// Bind the kind BEFORE the signature check: the kind is part of the signed bytes, so a mismatch
	// also fails verification — this explicit check gives a clear error and rejects a signed index of
	// the wrong kind even if an attacker could somehow present a valid-looking envelope.
	if si.GetKind() != wantKind {
		return nil, fmt.Errorf("index: kind is %q, expected %q", si.GetKind(), wantKind)
	}
	if !ed25519.Verify(trustedPub, indexSigningBytes(si.GetKind(), si.GetIndex()), si.GetSignature()) {
		return nil, fmt.Errorf("index: signature does not verify against the trusted operator key")
	}
	if len(si.GetIndex()) == 0 {
		return nil, fmt.Errorf("index: verified envelope carries no index")
	}
	return si.GetIndex(), nil
}

func validIndexKind(kind string) bool {
	switch kind {
	case IndexKindEDM, IndexKindRecord, IndexKindIDM:
		return true
	}
	return false
}
