// Package pseudonym holds the ONE canonical, one-way derivation that turns a raw
// identity (an enrolled agent identity, a client-certificate CN) into the stable
// pseudonymous subject used across the Zero-Trust surfaces (D23).
//
// It exists as its own zero-dependency package (only crypto/sha256, encoding/hex)
// precisely so both sides of the device-posture chain can share it without an
// awkward dependency: the endpoint posture publisher (internal/posture, linked into
// the fleet-agent) and the gateway (identity resolution + the posture roster) both
// import it, and neither drags in the other's packages (ADR-6, IDENT-1). Before this
// package the derivation was unexported inside internal/gateway/identity, so the
// publisher keyed posture by the raw agent id while the proxy looked it up under the
// pseudonym — the keys never matched and the posture chain was inert in production.
//
// The reverse mapping (pseudonym -> real identity) is a deployer concern behind an
// audited lookup; it never enters the pipeline.
package pseudonym

import (
	"crypto/sha256"
	"encoding/hex"
)

// domainSep namespaces the hash so a pseudonym derived here can never collide with a
// digest computed for another purpose over the same identity bytes.
const domainSep = "zt-client-subject:"

// Of returns the canonical pseudonymous subject for a raw identity: a domain-separated
// SHA-256 truncated to 12 bytes, hex-encoded, with a "sub_" marker. The output is
// stable — enrollment, the posture publisher, the posture roster/verifier, and the
// access proxy MUST all derive a subject through this one function so their keys match.
//
// The value is deliberately pinned by a golden test: changing the domain separator or
// the truncation would silently re-key every existing pseudonymous subject.
func Of(identity string) string {
	sum := sha256.Sum256([]byte(domainSep + identity))
	return "sub_" + hex.EncodeToString(sum[:12])
}
