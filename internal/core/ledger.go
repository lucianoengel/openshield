package core

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The audit ledger is tamper-EVIDENT with forward integrity between anchors.
// It is not tamper-proof, and no surface may say otherwise.
//
// What it protects: the past. An attacker who compromises the host at time T
// cannot alter or forge entries written before T.
//
// What it does not protect: the present or the future. That same attacker can
// suppress later entries, fabricate entries forward from T, or delete the whole
// ledger. Verification detects alteration; it cannot resurrect evidence that no
// longer exists.
//
// Two mechanisms, because neither alone is sufficient:
//
//  1. A hash chain: each entry commits to its predecessor, so editing one entry
//     invalidates every hash after it. Alone this is weak — an attacker holding
//     the signing key rewrites the whole history consistently.
//  2. An evolving KEYPAIR: each epoch generates a fresh Ed25519 key, publishes
//     its public half signed by the previous epoch's private key, then destroys
//     that private key. Alone this is also weak — entries are individually
//     authentic but their order and completeness are unprotected.
//
// Together, the tail an attacker can rewrite begins at the moment of compromise.
//
// This was a SYMMETRIC ratchet (K(n+1) = H(K(n))) until it was found to provide
// no forward integrity at all: verification needed the seed, and the seed
// forges. The only party able to verify the log was the only party able to fake
// it. The asymmetric design exists specifically so verification takes public
// material only — see docs/decisions.md D30.

// RetentionClass drives the purge job (T-013). Recorded from the first
// migration because adding a column to a hash-chained ledger later changes what
// is hashed and breaks continuity at that point.
type RetentionClass int32

const (
	RetentionUnspecified RetentionClass = iota
	RetentionShort                      // routine telemetry
	RetentionStandard                   // ordinary decisions
	RetentionInvestigation              // held for an open investigation
)

// Entry is one record in the ledger.
type Entry struct {
	Sequence  uint64
	AppendedAt time.Time

	Decision       *corev1.Decision
	SubjectID      string // pseudonymous (D23)
	Purpose        corev1.Purpose
	ContextVersion string // D27
	Retention      RetentionClass

	// Outcome records pipeline terminations that produced no Decision —
	// timeouts and stage failures. An Event that produced no Decision is not
	// the same as one that was allowed, and the ledger must not conflate them.
	OutcomeKind string
	OutcomeStage string

	// KeyEpoch is the epoch whose key signed this entry. Hashed, so an attacker
	// cannot re-point an entry at an epoch whose key they hold.
	KeyEpoch uint64

	PrevHash []byte
	Hash     []byte
	Sig      []byte
}

// canonicalBytes produces the exact byte string that is hashed and signed.
//
// Deliberately NOT protobuf marshalling. Proto serialization is not guaranteed
// canonical — field ordering and unknown-field retention can vary between
// versions and implementations — and a chain whose hash depends on a
// serializer's incidental behaviour is a chain that breaks on a library
// upgrade. Every field is written explicitly, length-prefixed, in a fixed
// order, so the encoding is reviewable by reading this function.
func (e *Entry) canonicalBytes() []byte {
	var b []byte
	u64 := func(v uint64) {
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], v)
		b = append(b, t[:]...)
	}
	// Length-prefixed, so that ("ab","c") and ("a","bc") cannot collide.
	str := func(s string) {
		u64(uint64(len(s)))
		b = append(b, s...)
	}
	raw := func(p []byte) {
		u64(uint64(len(p)))
		b = append(b, p...)
	}

	u64(e.Sequence)
	u64(e.KeyEpoch)
	u64(uint64(e.AppendedAt.UTC().UnixNano()))
	raw(e.PrevHash)
	str(e.SubjectID)
	u64(uint64(e.Purpose))
	str(e.ContextVersion)
	u64(uint64(e.Retention))
	str(e.OutcomeKind)
	str(e.OutcomeStage)

	if d := e.Decision; d != nil {
		str(d.GetDecisionId())
		str(d.GetEventId())
		u64(uint64(d.GetAction()))
		u64(uint64(int64(d.GetConfidence() * 1e9))) // fixed-point: float bits are not portable
		str(d.GetReason())
		str(d.GetPolicyId())
		str(d.GetPolicyVersion())
		str(d.GetContextVersion())
	} else {
		str("") // presence marker, so a nil Decision cannot collide with an empty one
	}
	return b
}

// GenesisHash anchors the first entry. Recorded explicitly rather than left as
// an implicit zero, so "the chain starts here" is a claim in the data.
var GenesisHash = sha256.Sum256([]byte("openshield.audit.genesis.v1"))

// KeyEpoch is one link in the public-key chain.
//
// Each epoch's public key is signed by the PREVIOUS epoch's private key, which
// is then destroyed. Verification walks forward from the anchor using only
// public material — there is no secret anywhere in the verification path, which
// is the property a symmetric scheme could not provide.
type KeyEpoch struct {
	Index uint64
	// PublicKey signs entries in this epoch.
	PublicKey ed25519.PublicKey
	// SigByPrev is PublicKey signed by epoch Index-1's private key. Empty for
	// the anchor epoch, whose authenticity comes from being published
	// out-of-band rather than from a predecessor.
	SigByPrev []byte
}

// Signer holds the CURRENT private key and nothing else.
//
// It cannot reconstruct a prior private key: prior keys are generated
// independently and destroyed, not derived. That is what makes compromise at
// epoch N unable to forge epoch N-1 — and it is the specific thing the previous
// symmetric implementation got wrong by retaining a master seed.
//
// HONEST LIMIT: destroying a key means overwriting it in memory, which Go's GC
// makes best-effort — copies may survive. The realistic protection is that the
// window is short and an attacker reading agent memory has already won on other
// fronts. Claiming erasure would overstate what the runtime supports.
type Signer struct {
	epoch uint64
	priv  ed25519.PrivateKey
	chain []KeyEpoch
}

// NewSigner creates the anchor epoch. PK_0 must be published out-of-band; a
// verifier that takes the anchor from the same host that could have rewritten
// the log gains little (see design.md, open question 4).
func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generating anchor key: %w", err)
	}
	return &Signer{
		priv:  priv,
		chain: []KeyEpoch{{Index: 0, PublicKey: pub}},
	}, nil
}

// Evolve advances to the next epoch: generate a keypair, sign the new public
// key with the current private key, then destroy the current private key.
func (s *Signer) Evolve() error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generating epoch key: %w", err)
	}
	sig := ed25519.Sign(s.priv, pub)

	for i := range s.priv { // best-effort destruction; see the type comment
		s.priv[i] = 0
	}
	s.priv = priv
	s.epoch++
	s.chain = append(s.chain, KeyEpoch{Index: s.epoch, PublicKey: pub, SigByPrev: sig})
	return nil
}

func (s *Signer) Epoch() uint64      { return s.epoch }
func (s *Signer) Chain() []KeyEpoch  { return append([]KeyEpoch{}, s.chain...) }
func (s *Signer) AnchorKey() ed25519.PublicKey {
	return s.chain[0].PublicKey
}

// Seal computes an entry's hash and signs it with the current epoch key.
func (s *Signer) Seal(e *Entry, prevHash []byte) {
	e.PrevHash = prevHash
	e.KeyEpoch = s.epoch
	h := sha256.Sum256(e.canonicalBytes())
	e.Hash = h[:]
	e.Sig = ed25519.Sign(s.priv, e.Hash)
}

// VerifyKeyChain walks the public-key chain from the anchor using ONLY public
// material. Returns the per-epoch public keys if the chain is sound.
func VerifyKeyChain(chain []KeyEpoch, anchor ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	if len(chain) == 0 {
		return nil, errors.New("ledger: empty key chain")
	}
	if !chain[0].PublicKey.Equal(anchor) {
		return nil, errors.New("ledger: key chain does not start at the published anchor")
	}
	keys := []ed25519.PublicKey{chain[0].PublicKey}
	for i := 1; i < len(chain); i++ {
		if !ed25519.Verify(chain[i-1].PublicKey, chain[i].PublicKey, chain[i].SigByPrev) {
			return nil, fmt.Errorf("ledger: epoch %d public key is not signed by epoch %d", i, i-1)
		}
		keys = append(keys, chain[i].PublicKey)
	}
	return keys, nil
}

// Completeness distinguishes "the chain is internally consistent" from
// "nothing was removed". They are different claims and a boolean cannot carry
// both — between external anchors a root attacker can destroy the chain and
// build a shorter consistent one that verifies perfectly.
type Completeness int

const (
	// CompletenessUnverified: internally consistent, but nothing external
	// attests that entries were not removed wholesale. This is the honest
	// answer whenever no anchor exists (T-019).
	CompletenessUnverified Completeness = iota
	// CompletenessAnchored: an external witness attests to the range.
	CompletenessAnchored
	// CompletenessAbsent: the chain is missing or truncated.
	CompletenessAbsent
)

func (c Completeness) String() string {
	switch c {
	case CompletenessAnchored:
		return "anchored"
	case CompletenessAbsent:
		return "absent"
	default:
		return "unverified"
	}
}

// VerifyResult is deliberately not a bool.
type VerifyResult struct {
	Consistent   bool
	Completeness Completeness
	FromSequence uint64
	ToSequence   uint64
	Entries      int
	// FirstBreak locates the tampering rather than merely reporting it.
	FirstBreak *uint64
	Reason     string
}

func (v VerifyResult) String() string {
	s := fmt.Sprintf("consistent=%v entries=%d range=[%d,%d] completeness=%s",
		v.Consistent, v.Entries, v.FromSequence, v.ToSequence, v.Completeness)
	if v.FirstBreak != nil {
		s += fmt.Sprintf(" first_break=%d", *v.FirstBreak)
	}
	if v.Reason != "" {
		s += " reason=" + v.Reason
	}
	return s
}

var (
	ErrLedgerUnavailable = errors.New("ledger: unavailable")
	ErrAppendFailed      = errors.New("ledger: append failed")
)

// Ledger is the audit store. The interface lives in core; implementations live
// outside it, and core must not import a database driver — same boundary and
// same reasoning as the transport (D24).
type Ledger interface {
	// Append records an entry. A failed append MUST return an error: an
	// unrecorded Decision in an observe-only product is indistinguishable from
	// an event that never happened.
	Append(ctx context.Context, e *Entry) error
	// Verify walks the chain.
	Verify(ctx context.Context) (VerifyResult, error)
	Close() error
}

// VerifyChain checks a materialised sequence of entries against a seed.
//
// Tested against specific attacks — edit, delete, reorder, truncate, and
// forging an early entry with a later key — rather than by round-tripping a
// valid chain. A chain implementation that is subtly wrong still round-trips.
func VerifyChain(entries []*Entry, chain []KeyEpoch, anchor ed25519.PublicKey, anchored bool) VerifyResult {
	res := VerifyResult{Consistent: true, Entries: len(entries)}
	res.Completeness = CompletenessUnverified
	if anchored {
		res.Completeness = CompletenessAnchored
	}
	if len(entries) == 0 {
		res.Completeness = CompletenessAbsent
		res.Consistent = false
		res.Reason = "chain is empty or absent"
		return res
	}

	keys, err := VerifyKeyChain(chain, anchor)
	if err != nil {
		res.Consistent = false
		res.Reason = err.Error()
		return res
	}

	res.FromSequence = entries[0].Sequence
	res.ToSequence = entries[len(entries)-1].Sequence

	prev := GenesisHash[:]
	for _, e := range entries {
		seq := e.Sequence
		fail := func(reason string) VerifyResult {
			res.Consistent = false
			res.FirstBreak = &seq
			res.Reason = reason
			return res
		}
		if !hmac.Equal(e.PrevHash, prev) {
			return fail("previous-hash mismatch: an entry was edited, deleted or reordered")
		}
		want := sha256.Sum256(e.canonicalBytes())
		if !hmac.Equal(e.Hash, want[:]) {
			return fail("entry hash does not match its content: entry was modified")
		}
		if e.KeyEpoch >= uint64(len(keys)) {
			return fail("entry references an epoch beyond the key chain")
		}
		if !ed25519.Verify(keys[e.KeyEpoch], e.Hash, e.Sig) {
			return fail("signature invalid for the epoch key this entry claims")
		}
		prev = e.Hash
	}
	return res
}

// RecomputeHashForTest recomputes an entry's hash over its current content.
//
// Exported for attack tests only. It models what an attacker can trivially do:
// the entry hash is unkeyed and computed over public content, so recomputing it
// after modification is free. What they cannot do is produce a matching
// signature — which is why the signature check must be independently tested,
// and why an earlier version of these tests proved less than it appeared to.
func RecomputeHashForTest(e *Entry) {
	h := sha256.Sum256(e.canonicalBytes())
	e.Hash = h[:]
}
