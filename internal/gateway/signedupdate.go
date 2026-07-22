package gateway

import (
	"crypto/ed25519"
	"fmt"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// SignUpdate wraps a marshalled payload (a RiskUpdate / PostureUpdate) in a SignedUpdate,
// signing the payload bytes with the publisher's Ed25519 private key (SEC-1). This is the
// publisher side; the gateway verifies with verifySignedUpdate.
func SignUpdate(payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	sig := ed25519.Sign(priv, payload)
	return proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: sig})
}

// verifySignedUpdate decodes a SignedUpdate and verifies its signature against the trusted
// publisher key BEFORE the caller interprets the payload (SEC-1) — an unverified update's
// contents never reach the store. It returns the verified payload bytes, or an error if the
// envelope is malformed, unsigned, or the signature does not verify. A caller that receives
// an error MUST drop and COUNT the update, never apply it (fail-closed).
// splitSignedUpdate parses the envelope and returns the payload and signature WITHOUT verifying —
// the caller verifies against the appropriate key. Posture (SEC-12) must verify against the
// REPORTING AGENT's own enrolled key (bound to the update's subject), not a shared key, so it needs
// the payload to read the subject before it can pick the key; the security check is still
// verify-BEFORE-apply. Risk stays on verifySignedUpdate (a single control-plane key, SEC-1).
func splitSignedUpdate(data []byte) (payload, sig []byte, err error) {
	var su corev1.SignedUpdate
	if err := proto.Unmarshal(data, &su); err != nil {
		return nil, nil, fmt.Errorf("gateway: malformed signed update: %w", err)
	}
	if len(su.GetSignature()) == 0 {
		return nil, nil, fmt.Errorf("gateway: update is unsigned")
	}
	return su.GetPayload(), su.GetSignature(), nil
}

func verifySignedUpdate(data []byte, trustedPub ed25519.PublicKey) ([]byte, error) {
	if len(trustedPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway: trusted publisher key must be %d bytes", ed25519.PublicKeySize)
	}
	var su corev1.SignedUpdate
	if err := proto.Unmarshal(data, &su); err != nil {
		return nil, fmt.Errorf("gateway: malformed signed update: %w", err)
	}
	if len(su.GetSignature()) == 0 {
		return nil, fmt.Errorf("gateway: update is unsigned")
	}
	if !ed25519.Verify(trustedPub, su.GetPayload(), su.GetSignature()) {
		return nil, fmt.Errorf("gateway: signed update does not verify against the trusted key")
	}
	return su.GetPayload(), nil
}
