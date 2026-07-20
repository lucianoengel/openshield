package core_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The ledger is tested against SPECIFIC attacks — edit, delete, reorder,
// truncate, and forging an early entry with a later key — rather than by
// round-tripping a valid chain. A chain implementation that is subtly wrong
// still round-trips perfectly; that is exactly why round-tripping proves
// nothing here.

var testSeed = []byte("test-seed-not-a-real-key")

// buildChain produces n sealed entries, as the ledger would.
func buildChain(t *testing.T, n int) []*core.Entry {
	t.Helper()
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
		core.Seal(e, prev, core.KeyAt(testSeed, uint64(i)))
		prev = e.Hash
		entries = append(entries, e)
	}
	return entries
}

func TestValidChainVerifies(t *testing.T) {
	res := core.VerifyChain(buildChain(t, 5), testSeed, false)
	if !res.Consistent {
		t.Fatalf("valid chain failed to verify: %s", res)
	}
	if res.Entries != 5 {
		t.Errorf("entries = %d, want 5", res.Entries)
	}
}

// Task 2.3 — editing an entry in place must be detected AND located.
func TestEditedEntryIsDetectedAndLocated(t *testing.T) {
	entries := buildChain(t, 5)
	entries[2].Decision.Reason = "tampered"

	res := core.VerifyChain(entries, testSeed, false)
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
func TestDeletedEntryIsDetected(t *testing.T) {
	entries := buildChain(t, 5)
	shortened := append(append([]*core.Entry{}, entries[:2]...), entries[3:]...)

	res := core.VerifyChain(shortened, testSeed, false)
	if res.Consistent {
		t.Fatal("a deleted entry verified — suppression would be invisible")
	}
	if res.FirstBreak == nil || *res.FirstBreak != 3 {
		t.Errorf("first break = %v, want 3 (the entry following the deletion)", res.FirstBreak)
	}
}

// Task 2.5 — reordering must be detected. Individually authentic entries in the
// wrong order would otherwise pass, which is the gap a hash chain closes and a
// signature alone does not.
func TestReorderedEntriesAreDetected(t *testing.T) {
	entries := buildChain(t, 5)
	entries[1], entries[2] = entries[2], entries[1]

	res := core.VerifyChain(entries, testSeed, false)
	if res.Consistent {
		t.Fatal("reordered entries verified — order is unprotected")
	}
}

// Truncation must report absence, not success. A shorter but internally
// consistent chain is exactly what a root attacker would leave behind.
func TestTruncatedChainReportsAbsence(t *testing.T) {
	res := core.VerifyChain(nil, testSeed, false)
	if res.Consistent {
		t.Fatal("an empty chain reported as consistent")
	}
	if res.Completeness != core.CompletenessAbsent {
		t.Errorf("completeness = %v, want absent", res.Completeness)
	}
}

// Task 3.2 — THE forward-integrity test.
//
// Given the key in force at entry N, an attacker must not be able to forge a
// valid entry before N. This is what makes the rewritable tail begin at the
// moment of compromise; without it, a compromised key rewrites all history.
func TestKeyFromLaterEntryCannotForgeAnEarlierOne(t *testing.T) {
	const compromiseAt = 3
	entries := buildChain(t, 6)

	// The attacker holds the key in force at entry 3 and everything derivable
	// from it (the ratchet is one-way, so that is keys 3, 4, 5, ...).
	compromisedKey := core.KeyAt(testSeed, compromiseAt)

	// They can forge entry 3 onwards — this must SUCCEED, or the test is not
	// describing the real threat model.
	forgedLater := buildChain(t, 6)[compromiseAt]
	forgedLater.Decision.Reason = "forged-after-compromise"
	core.Seal(forgedLater, entries[compromiseAt].PrevHash, compromisedKey)
	m := hmac.New(sha256.New, compromisedKey)
	m.Write(forgedLater.Hash)
	if !hmac.Equal(forgedLater.Sig, m.Sum(nil)) {
		t.Fatal("attacker could not forge a POST-compromise entry; the test's premise is wrong")
	}

	// Now the actual claim: they cannot produce a valid entry 1.
	forgedEarlier := buildChain(t, 6)[1]
	forgedEarlier.Decision.Reason = "forged-before-compromise"
	core.Seal(forgedEarlier, entries[1].PrevHash, compromisedKey)

	// Verification derives the key for position 1 from the seed. The attacker
	// does not have that key and cannot derive it from a later one.
	tampered := buildChain(t, 6)
	tampered[1] = forgedEarlier
	res := core.VerifyChain(tampered, testSeed, false)
	if res.Consistent {
		t.Fatal("an entry forged with a POST-compromise key verified — forward integrity " +
			"is not achieved, and a compromised host can rewrite all history")
	}
}

// The ratchet must be one-way: a later key must not reveal an earlier one.
func TestRatchetIsOneWay(t *testing.T) {
	k3 := core.KeyAt(testSeed, 3)
	k4 := core.KeyAt(testSeed, 4)
	if hmac.Equal(k3, k4) {
		t.Fatal("ratchet did not evolve the key")
	}
	// K4 = H(K3). The reverse must not hold for any trivial relation.
	forward := sha256.Sum256(k3)
	if !hmac.Equal(forward[:], k4) {
		t.Fatal("ratchet is not K(n+1) = H(K(n)) as documented")
	}
	back := sha256.Sum256(k4)
	if hmac.Equal(back[:], k3) {
		t.Fatal("hashing forward from K4 reproduced K3 — the ratchet is reversible")
	}
}

// Task 4.2 — a consistent chain with no anchor must NOT report success on
// completeness. Between anchors a root attacker can destroy the chain and build
// a shorter consistent one that verifies perfectly.
func TestConsistentButUnanchoredReportsCompletenessUnverified(t *testing.T) {
	res := core.VerifyChain(buildChain(t, 4), testSeed, false)
	if !res.Consistent {
		t.Fatalf("valid chain failed: %s", res)
	}
	if res.Completeness != core.CompletenessUnverified {
		t.Errorf("completeness = %v, want unverified — internal consistency is not "+
			"evidence that nothing was removed", res.Completeness)
	}
	// And the result must be structured, not collapsible to a bare boolean.
	if res.String() == "" || res.ToSequence != 3 {
		t.Errorf("result does not carry its range: %s", res)
	}
}

func TestAnchoredChainReportsAnchored(t *testing.T) {
	res := core.VerifyChain(buildChain(t, 4), testSeed, true)
	if res.Completeness != core.CompletenessAnchored {
		t.Errorf("completeness = %v, want anchored", res.Completeness)
	}
}

// The canonical encoding must be length-prefixed so adjacent fields cannot be
// shifted between each other without changing the hash.
func TestCanonicalEncodingResistsFieldShifting(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	mk := func(subject, ctxVer string) *core.Entry {
		e := &core.Entry{Sequence: 1, AppendedAt: base, SubjectID: subject, ContextVersion: ctxVer}
		core.Seal(e, core.GenesisHash[:], core.KeyAt(testSeed, 1))
		return e
	}
	a := mk("ab", "c")
	b := mk("a", "bc")
	if hmac.Equal(a.Hash, b.Hash) {
		t.Error("(\"ab\",\"c\") and (\"a\",\"bc\") hash identically — the encoding is not " +
			"length-prefixed and fields can be shifted without detection")
	}
}

// A nil Decision must not hash the same as an empty one: "no decision was made"
// and "a decision was made with empty fields" are different facts.
func TestNilDecisionDoesNotCollideWithEmpty(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	withNil := &core.Entry{Sequence: 1, AppendedAt: base}
	core.Seal(withNil, core.GenesisHash[:], core.KeyAt(testSeed, 1))

	withEmpty := &core.Entry{Sequence: 1, AppendedAt: base, Decision: &corev1.Decision{}}
	core.Seal(withEmpty, core.GenesisHash[:], core.KeyAt(testSeed, 1))

	if hmac.Equal(withNil.Hash, withEmpty.Hash) {
		t.Error("a nil Decision hashes identically to an empty one")
	}
}
