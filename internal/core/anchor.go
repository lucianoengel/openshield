package core

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
)

// Anchor is a witnessed checkpoint of the ledger head (T-019).
//
// It records that at some moment the ledger's latest entry was Sequence, with
// Hash. Because the chain is LINEAR, that head hash commits to the whole prefix
// [0, Sequence] — so a single checkpoint attests to everything up to it, with no
// Merkle inclusion proof needed.
//
// WitnessSig is what makes an anchor evidence rather than decoration. It is
// signed by a Witness whose key lives in a DIFFERENT trust domain than the
// ledger Signer: an anchor the agent could forge proves nothing, because the
// agent is the party that might rewrite the log.
type Anchor struct {
	Sequence   uint64
	Hash       []byte
	WitnessSig []byte
}

// canonicalAnchorBytes is the exact input to the witness signature:
// length-prefixed (sequence, hash), the same discipline as entry hashing, so the
// signed bytes are reviewable and cannot collide.
func canonicalAnchorBytes(seq uint64, hash []byte) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	out := append([]byte("openshield.anchor.v1"), b[:]...)
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(hash)))
	out = append(out, l[:]...)
	out = append(out, hash...)
	return out
}

// Witness holds the anchoring private key. It is deliberately a distinct type
// from Signer and MUST be provisioned in a trust domain the deployer does not
// control (a second host, WORM storage, a public transparency service) — an
// anchor witnessed by a key the deployer holds is theatre.
type Witness struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewWitness creates a witness keypair.
func NewWitness() (*Witness, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generating witness key: %w", err)
	}
	return &Witness{priv: priv, pub: pub}, nil
}

// PublicKey is the material a verifier needs — and all it needs.
func (w *Witness) PublicKey() ed25519.PublicKey { return w.pub }

// Anchor signs a checkpoint of (seq, hash).
func (w *Witness) Anchor(seq uint64, hash []byte) Anchor {
	sig := ed25519.Sign(w.priv, canonicalAnchorBytes(seq, hash))
	h := make([]byte, len(hash))
	copy(h, hash)
	return Anchor{Sequence: seq, Hash: h, WitnessSig: sig}
}

// VerifyAnchor checks the witness signature using only public material.
func VerifyAnchor(a Anchor, witnessPub ed25519.PublicKey) bool {
	if len(witnessPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(witnessPub, canonicalAnchorBytes(a.Sequence, a.Hash), a.WitnessSig)
}

// checkAnchors verifies each anchor against the chain and returns the highest
// witnessed sequence. It fails (ok=false) if a valid witness anchor's checkpoint
// is not satisfied by the chain — a truncation or rewrite of witnessed history.
//
// bySeq maps sequence → stored hash for the entries actually present.
func checkAnchors(anchors []Anchor, witnessPub ed25519.PublicKey, bySeq map[uint64][]byte) (anchoredThrough uint64, violated *Anchor, ok bool) {
	for i := range anchors {
		a := anchors[i]
		if !VerifyAnchor(a, witnessPub) {
			// An anchor we cannot attribute to the witness is ignored, not a
			// failure: a forged anchor must not be able to fail an honest chain.
			continue
		}
		storedHash, present := bySeq[a.Sequence]
		if !present || !hmac.Equal(storedHash, a.Hash) {
			// A witnessed checkpoint the chain no longer satisfies: witnessed
			// history was truncated or rewritten.
			v := a
			return 0, &v, false
		}
		if a.Sequence > anchoredThrough {
			anchoredThrough = a.Sequence
		}
	}
	return anchoredThrough, nil, true
}
