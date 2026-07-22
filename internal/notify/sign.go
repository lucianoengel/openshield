package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignatureHeader carries the HMAC of a signed webhook body (SIEM-8). The name and the
// "sha256=<hex>" value format follow the GitHub webhook convention so an off-the-shelf
// receiver library can verify it.
const SignatureHeader = "X-Openshield-Signature"

// Sign returns the signature for body under secret: "sha256=" + hex(HMAC-SHA256). A
// receiver holding the same secret recomputes it over the exact bytes it received and
// compares (see VerifySignature) to confirm the alert came from this control plane and
// was not tampered with — a webhook URL is otherwise an unauthenticated open endpoint.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether header is a valid signature of body under secret. The
// comparison is CONSTANT-TIME (hmac.Equal) so a forger cannot recover the expected MAC
// byte-by-byte via timing. A malformed, absent, or wrong-length header returns false
// without leaking where it diverged.
func VerifySignature(secret, body []byte, header string) bool {
	expected := Sign(secret, body)
	// hmac.Equal is constant-time for equal-length inputs and length-safe otherwise.
	return hmac.Equal([]byte(header), []byte(expected))
}
