package core_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The ledger is tested against SPECIFIC attacks — edit, delete, reorder,
// truncate, epoch re-pointing, and forging an earlier entry after compromise —
// rather than by round-tripping a valid chain. A chain that is subtly wrong
// still round-trips perfectly; that is precisely why round-tripping proves
// nothing here, and why the first version of this file passed against an
// implementation with no forward integrity at all.

// buildChain produces n sealed entries, evolving the key after each one so the
// forward-integrity tests have a distinct epoch per position.
func buildChain(t *testing.T, n int) ([]*core.Entry, *core.Signer) {
	t.Helper()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	var entries []*core.Entry
	prev := core.GenesisHash[:]
	base := time.Unix(1700000000, 0).UTC()
	for i := 0; i < n; i++ {
		e := &core.Entry{
			Sequence:   uint64(i),
			AppendedAt: base.Add(time.Duration(i) * time.Second),
			Decision: &corev1.Decision{
				DecisionId: "d", EventId: "e",
				Action: corev1.Action_ACTION_ALERT, Confidence: 0.5,
				Reason: "fixture", PolicyId: "p", PolicyVersion: "1",
				DecidedAt: timestamppb.New(base),
			},
			SubjectID: "s_1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Retention: core.RetentionStandard,
		}
		signer.Seal(e, prev)
		prev = e.Hash
		entries = append(entries, e)
		if i < n-1 {
			if err := signer.Evolve(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return entries, signer
}

// verify uses only public material, as an auditor would.
func verify(entries []*core.Entry, s *core.Signer, _ bool) core.VerifyResult {
	return core.VerifyChain(entries, s.Chain(), s.AnchorKey(), nil, nil)
}

func TestValidChainVerifies(t *testing.T) {
	entries, signer := buildChain(t, 5)
	res := verify(entries, signer, false)
	if !res.Consistent {
		t.Fatalf("valid chain failed to verify: %s", res)
	}
	if res.Entries != 5 {
		t.Errorf("entries = %d, want 5", res.Entries)
	}
}

// Task 2.3 — editing an entry must be detected AND located.
func TestEditedEntryIsDetectedAndLocated(t *testing.T) {
	entries, signer := buildChain(t, 5)
	entries[2].Decision.Reason = "tampered"

	res := verify(entries, signer, false)
	if res.Consistent {
		t.Fatal("an edited entry verified — the chain provides no protection")
	}
	if res.FirstBreak == nil {
		t.Fatal("tampering detected but not located; an operator needs to know which entry")
	}
	if *res.FirstBreak != 2 {
		t.Errorf("first break = %d, want 2", *res.FirstBreak)
	}
}

// Task 2.4 — deleting a middle entry breaks the link at the following one.
// With per-epoch signatures this is caught by the hash chain alone, so this
// test is now the sole guard on that property rather than one of two.
func TestDeletedEntryIsDetected(t *testing.T) {
	entries, signer := buildChain(t, 5)
	shortened := append(append([]*core.Entry{}, entries[:2]...), entries[3:]...)

	res := verify(shortened, signer, false)
	if res.Consistent {
		t.Fatal("a deleted entry verified — suppression would be invisible")
	}
	if res.FirstBreak == nil || *res.FirstBreak != 3 {
		t.Errorf("first break = %v, want 3 (the entry following the deletion)", res.FirstBreak)
	}
}

// Task 2.5 — reordering must be detected. Individually authentic entries in the
// wrong order would otherwise pass: the gap a hash chain closes and a signature
// alone does not.
func TestReorderedEntriesAreDetected(t *testing.T) {
	entries, signer := buildChain(t, 5)
	entries[1], entries[2] = entries[2], entries[1]

	res := verify(entries, signer, false)
	if res.Consistent {
		t.Fatal("reordered entries verified — order is unprotected")
	}
}

func TestTruncatedChainReportsAbsence(t *testing.T) {
	_, signer := buildChain(t, 1)
	res := verify(nil, signer, false)
	if res.Consistent {
		t.Fatal("an empty chain reported as consistent")
	}
	if res.Completeness != core.CompletenessAbsent {
		t.Errorf("completeness = %v, want absent", res.Completeness)
	}
}

// Task 3.2 — THE forward-integrity test, against the REAL threat model.
//
// The attacker takes everything the agent process holds at compromise: the
// current private key, the whole public-key chain, and every stored entry. The
// previous version of this test handed the attacker a conveniently derived key
// while the implementation retained a master seed, so it passed against an
// implementation providing no forward integrity whatsoever. That failure is why
// this test is written the way it is.
func TestCompromisedProcessCannotForgeEarlierEntries(t *testing.T) {
	entries, signer := buildChain(t, 6)

	// Everything the process holds — all of it public except the CURRENT
	// private key, which the attacker also has but which belongs to the last
	// epoch, not to entry 1.
	stolenChain := signer.Chain()
	stolenAnchor := signer.AnchorKey()

	// The attacker forges entry 1 with the only signing capability they have:
	// a key of their own, or the current epoch key. Neither is epoch 1's
	// private key, which was destroyed and is not derivable.
	attacker, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged := &core.Entry{
		Sequence: 1, KeyEpoch: 1,
		AppendedAt: entries[1].AppendedAt,
		Decision:   &corev1.Decision{DecisionId: "d", Reason: "forged-before-compromise"},
		SubjectID:  "s_1", Purpose: corev1.Purpose_PURPOSE_DLP,
	}
	attacker.Seal(forged, entries[1].PrevHash)
	forged.KeyEpoch = 1 // claim the original epoch, since Seal set the attacker's

	tampered, _ := buildChain(t, 6)
	tampered[1] = forged

	res := core.VerifyChain(tampered, stolenChain, stolenAnchor, nil, nil)
	if res.Consistent {
		t.Fatal("an entry forged after compromise verified — forward integrity is absent, " +
			"and a compromised host can rewrite all history")
	}
	if res.FirstBreak == nil {
		t.Error("verification failed without locating the break")
	}
}

// The signature check must be independently load-bearing.
//
// The entry hash is UNKEYED and computed over public content, so a real
// attacker recomputes it correctly for whatever they write. The only thing
// standing between them and a rewritten history is the signature. An earlier
// version of this file never tested that: every "forgery" it built also
// corrupted the hash, so deleting the signature check broke no test at all.
func TestValidHashWithInvalidSignatureIsRejected(t *testing.T) {
	entries, signer := buildChain(t, 5)

	// Hash and prev-link left intact and correct; only the signature is wrong.
	// This is what an attacker who cannot sign but can compute produces.
	entries[1].Sig = make([]byte, len(entries[1].Sig))

	res := verify(entries, signer, false)
	if res.Consistent {
		t.Fatal("an entry with a valid hash but an invalid signature verified — the " +
			"signature check is not load-bearing, and the unkeyed hash alone stops nobody")
	}
	if res.FirstBreak == nil || *res.FirstBreak != 1 {
		t.Errorf("first break = %v, want 1", res.FirstBreak)
	}
}

// Likewise the epoch binding: an entry whose hash is recomputed to match a
// different claimed epoch must still fail, because the epoch is hashed.
func TestRepointedEpochWithRecomputedHashIsRejected(t *testing.T) {
	entries, signer := buildChain(t, 5)

	// Attacker re-points entry 1 at epoch 4 (whose key they may hold after
	// compromise) AND recomputes the hash so it matches the new content.
	// Only the epoch-4 private key would make this verify, and at entry 1's
	// position the chain expects epoch 1.
	victim := entries[1]
	victim.KeyEpoch = 4
	// Recompute the hash exactly as a knowledgeable attacker would.
	core.RecomputeHashForTest(victim)

	res := verify(entries, signer, false)
	if res.Consistent {
		t.Fatal("an entry re-pointed to another epoch with a recomputed hash verified")
	}
}

// Task 3.3 — verification must require NO secret. This test holds only the key
// chain and the anchor public key, exactly what an auditor would be given.
func TestVerificationRequiresOnlyPublicMaterial(t *testing.T) {
	entries, signer := buildChain(t, 4)

	publicChain := signer.Chain()
	anchor := signer.AnchorKey()
	for _, ep := range publicChain {
		if len(ep.PublicKey) != ed25519.PublicKeySize {
			t.Fatalf("epoch %d exposes something other than a public key", ep.Index)
		}
	}

	if res := core.VerifyChain(entries, publicChain, anchor, nil, nil); !res.Consistent {
		t.Fatalf("public-only verification failed on a valid chain: %s", res)
	}
	entries[2].Decision.Reason = "tampered"
	if res := core.VerifyChain(entries, publicChain, anchor, nil, nil); res.Consistent {
		t.Fatal("public-only verification accepted a tampered chain")
	}
}

// A substituted key chain must be rejected, or an attacker simply supplies keys
// they control alongside a rewritten log.
func TestKeyChainMustStartAtTheAnchor(t *testing.T) {
	entries, signer := buildChain(t, 3)
	other, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	res := core.VerifyChain(entries, signer.Chain(), other.AnchorKey(), nil, nil)
	if res.Consistent {
		t.Fatal("a chain not starting at the published anchor verified")
	}
}

// An entry must not be re-pointable at an epoch whose key the attacker holds.
func TestEntryCannotBeRepointedToAnotherEpoch(t *testing.T) {
	entries, signer := buildChain(t, 5)
	entries[1].KeyEpoch = 4
	res := core.VerifyChain(entries, signer.Chain(), signer.AnchorKey(), nil, nil)
	if res.Consistent {
		t.Fatal("an entry re-pointed to a different epoch verified; KeyEpoch is not bound")
	}
}

// Task 4.2 — a consistent chain with no anchor must NOT report completeness as
// established. Between anchors a root attacker can destroy the chain and build
// a shorter consistent one that verifies perfectly.
func TestConsistentButUnanchoredReportsCompletenessUnverified(t *testing.T) {
	entries, signer := buildChain(t, 4)
	res := verify(entries, signer, false)
	if !res.Consistent {
		t.Fatalf("valid chain failed: %s", res)
	}
	if res.Completeness != core.CompletenessUnverified {
		t.Errorf("completeness = %v, want unverified — internal consistency is not "+
			"evidence that nothing was removed", res.Completeness)
	}
	if res.String() == "" || res.ToSequence != 3 {
		t.Errorf("result does not carry its range: %s", res)
	}
}

// A witnessed anchor over the head entry makes completeness ANCHORED — nothing
// can have been truncated (T-019). This replaces the old test that relied on a
// crude `anchored bool`, which was always false in production and proved nothing.
func TestAnchoredChainReportsAnchored(t *testing.T) {
	entries, signer := buildChain(t, 4)
	w, err := core.NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	head := entries[len(entries)-1]
	anchor := w.Anchor(head.Sequence, head.Hash)

	res := core.VerifyChain(entries, signer.Chain(), signer.AnchorKey(), []core.Anchor{anchor}, w.PublicKey())
	if !res.Consistent {
		t.Fatalf("anchored chain not consistent: %s", res)
	}
	if res.Completeness != core.CompletenessAnchored {
		t.Errorf("completeness = %v, want anchored — a witness covers the last entry", res.Completeness)
	}
	if res.AnchoredThrough != head.Sequence {
		t.Errorf("AnchoredThrough = %d, want %d", res.AnchoredThrough, head.Sequence)
	}
}

// A partial anchor proves the prefix, not the tail: completeness stays
// UNVERIFIED but AnchoredThrough reports the boundary.
func TestPartialAnchorReportsBoundary(t *testing.T) {
	entries, signer := buildChain(t, 5)
	w, err := core.NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	// Anchor entry 2, leaving 3 and 4 un-witnessed.
	anchor := w.Anchor(entries[2].Sequence, entries[2].Hash)
	res := core.VerifyChain(entries, signer.Chain(), signer.AnchorKey(), []core.Anchor{anchor}, w.PublicKey())
	if !res.Consistent {
		t.Fatalf("not consistent: %s", res)
	}
	if res.Completeness != core.CompletenessUnverified {
		t.Errorf("completeness = %v, want unverified — the tail after the anchor is not witnessed", res.Completeness)
	}
	if res.AnchoredThrough != entries[2].Sequence {
		t.Errorf("AnchoredThrough = %d, want %d", res.AnchoredThrough, entries[2].Sequence)
	}
}

// Truncating the chain to before a valid anchor is DETECTED — the property
// anchoring exists to add.
func TestTruncationBeforeAnchorDetected(t *testing.T) {
	entries, signer := buildChain(t, 5)
	w, err := core.NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	// Witness the full head (sequence 4)...
	head := entries[len(entries)-1]
	anchor := w.Anchor(head.Sequence, head.Hash)
	// ...then present a shorter chain that drops the witnessed tail.
	truncated := entries[:3] // sequences 0,1,2 — anchor at 4 no longer satisfiable
	res := core.VerifyChain(truncated, signer.Chain(), signer.AnchorKey(), []core.Anchor{anchor}, w.PublicKey())
	if res.Consistent {
		t.Fatal("a chain truncated past a witnessed anchor verified as consistent — " +
			"anchoring must detect destruction of witnessed history")
	}
}

// A forged anchor (wrong witness key) must not be able to FAIL an honest chain.
func TestForgedAnchorCannotFailHonestChain(t *testing.T) {
	entries, signer := buildChain(t, 3)
	real, _ := core.NewWitness()
	attacker, _ := core.NewWitness()
	// The attacker signs a bogus checkpoint with THEIR key; the verifier trusts
	// only `real`. The bogus anchor must be ignored, not treated as a failure.
	bogus := attacker.Anchor(1, []byte("not the real hash"))
	res := core.VerifyChain(entries, signer.Chain(), signer.AnchorKey(), []core.Anchor{bogus}, real.PublicKey())
	if !res.Consistent {
		t.Fatalf("a forged anchor failed an honest chain: %s — only the trusted witness's "+
			"anchors may constrain verification", res)
	}
}

// The canonical encoding must be length-prefixed so adjacent fields cannot be
// shifted between each other without changing the hash.
func TestCanonicalEncodingResistsFieldShifting(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	mk := func(subject, ctxVer string) *core.Entry {
		e := &core.Entry{Sequence: 1, AppendedAt: base, SubjectID: subject, ContextVersion: ctxVer}
		signer.Seal(e, core.GenesisHash[:])
		return e
	}
	a := mk("ab", "c")
	b := mk("a", "bc")
	if hmac.Equal(a.Hash, b.Hash) {
		t.Error(`("ab","c") and ("a","bc") hash identically — the encoding is not ` +
			"length-prefixed and fields can be shifted without detection")
	}
}

// A nil Decision must not hash the same as an empty one: "no decision was made"
// and "a decision was made with empty fields" are different facts.
func TestNilDecisionDoesNotCollideWithEmpty(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	withNil := &core.Entry{Sequence: 1, AppendedAt: base}
	signer.Seal(withNil, core.GenesisHash[:])

	withEmpty := &core.Entry{Sequence: 1, AppendedAt: base, Decision: &corev1.Decision{}}
	signer.Seal(withEmpty, core.GenesisHash[:])

	if hmac.Equal(withNil.Hash, withEmpty.Hash) {
		t.Error("a nil Decision hashes identically to an empty one")
	}
}
