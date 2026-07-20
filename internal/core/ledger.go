package core

import (
	"context"
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
//  2. A ratcheting key: K(n+1) = H(K(n)), with K(n) destroyed after use. Alone
//     this is also weak — entries are individually authentic but their order and
//     completeness are unprotected.
//
// Together, the tail an attacker can rewrite begins at the moment of compromise.

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

// Ratchet holds the evolving signing key.
//
// K(n+1) = H(K(n)); K(n) is overwritten after use.
//
// HONEST LIMIT: overwriting a key in Go is best-effort. The garbage collector
// may have copied the slice, and nothing here can force those copies to be
// erased. The realistic protection is that the window is short and an attacker
// reading agent memory has already won on other fronts. Claiming erasure would
// be a stronger statement than the runtime supports.
type Ratchet struct {
	key []byte
	n   uint64
}

func NewRatchet(seed []byte) *Ratchet {
	k := make([]byte, len(seed))
	copy(k, seed)
	return &Ratchet{key: k}
}

// Sign signs data with the current key, then evolves.
func (r *Ratchet) Sign(data []byte) []byte {
	m := hmac.New(sha256.New, r.key)
	m.Write(data)
	sig := m.Sum(nil)
	r.evolve()
	return sig
}

// KeyAt derives the key in force at index n from a seed. Used by verification,
// which must reconstruct historical keys — and is precisely why a recovered
// current key cannot forge the past: the ratchet is one-way.
func KeyAt(seed []byte, n uint64) []byte {
	k := make([]byte, len(seed))
	copy(k, seed)
	for i := uint64(0); i < n; i++ {
		s := sha256.Sum256(k)
		k = s[:]
	}
	return k
}

func (r *Ratchet) evolve() {
	next := sha256.Sum256(r.key)
	for i := range r.key { // best-effort overwrite; see the type comment
		r.key[i] = 0
	}
	r.key = next[:]
	r.n++
}

func (r *Ratchet) Index() uint64 { return r.n }

// Seal computes an entry's hash and signature, given the ratchet key in force.
func Seal(e *Entry, prevHash []byte, key []byte) {
	e.PrevHash = prevHash
	c := e.canonicalBytes()
	h := sha256.Sum256(c)
	e.Hash = h[:]
	m := hmac.New(sha256.New, key)
	m.Write(e.Hash)
	e.Sig = m.Sum(nil)
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
func VerifyChain(entries []*Entry, seed []byte, anchored bool) VerifyResult {
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

	res.FromSequence = entries[0].Sequence
	res.ToSequence = entries[len(entries)-1].Sequence

	prev := GenesisHash[:]
	for i, e := range entries {
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
		key := KeyAt(seed, uint64(i))
		m := hmac.New(sha256.New, key)
		m.Write(e.Hash)
		if !hmac.Equal(e.Sig, m.Sum(nil)) {
			return fail("signature invalid for the key in force at this position")
		}
		prev = e.Hash
	}
	return res
}
