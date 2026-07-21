// Package identity is the agent's per-agent cryptographic identity (T-017).
//
// Each agent has its OWN Ed25519 keypair — never a shared fleet secret, which
// review (A6) flagged as fleet-wide risk: one compromised agent would equal
// fleet compromise. The private key never leaves the host; compromising one
// agent yields one agent's key.
//
// The agent signs each telemetry envelope with a monotonic sequence, so the
// control plane can attribute it, detect suppression (a sequence gap), and
// revoke the agent. This is the audit log's evidentiary bar applied to
// telemetry: a trail that cannot reveal suppression is not evidentiary.
//
// HONEST LIMIT (D16): root on the host can read this private key and sign
// anything the agent could. The guarantee is attributable-and-revocable, not
// unforgeable-against-host-root.
package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Identity is one agent's signing identity.
type Identity struct {
	AgentID string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
}

// Generate creates a fresh per-agent keypair.
func Generate(agentID string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("identity: generating key: %w", err)
	}
	return &Identity{AgentID: agentID, priv: priv, pub: pub}, nil
}

// PublicKey is the material the control plane enrolls — and all it needs to
// verify. The private key is never exposed.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.pub }

// CanonicalEnvelope is the exact byte string signed and verified, length-
// prefixed so fields cannot be shifted between each other, same discipline as
// the ledger's canonical bytes. Exported so the verifier reconstructs identical
// input.
func CanonicalEnvelope(agentID string, seq uint64, payload []byte) []byte {
	var b []byte
	u64 := func(v uint64) {
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], v)
		b = append(b, t[:]...)
	}
	str := func(s string) {
		u64(uint64(len(s)))
		b = append(b, s...)
	}
	raw := func(p []byte) {
		u64(uint64(len(p)))
		b = append(b, p...)
	}
	b = append(b, "openshield.tel.v1"...)
	str(agentID)
	u64(seq)
	raw(payload)
	return b
}

// Sign signs a telemetry envelope for the given sequence and payload.
func (i *Identity) Sign(seq uint64, payload []byte) []byte {
	return ed25519.Sign(i.priv, CanonicalEnvelope(i.AgentID, seq, payload))
}
