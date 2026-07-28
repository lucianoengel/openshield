package gateway_test

import (
	"crypto/ed25519"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// signUpdateForTest builds a signed-update envelope the way the control plane does.
//
// It is a TEST helper deliberately: the gateway only verifies, and a signing function in its
// production surface was a second producer of an envelope the control plane already produces. Kept
// here so the tests can still construct one, and so the duplication is visibly a test concern.
func signUpdateForTest(payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	sig := ed25519.Sign(priv, payload)
	return proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: sig})
}
