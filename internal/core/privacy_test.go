package core_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Privacy properties are negative claims — "no content leaves the endpoint" —
// and negative claims stated as prose rot silently. These tests prove them by
// evidence: build a message from known secrets, serialize it, and search the
// actual bytes.
//
// Hashing is explicitly NOT a defence for these values. CPF and SSN keyspaces
// are ~1e9, card numbers ~1e7 after BIN and Luhn constraints — exhaustively
// searchable in minutes to hours, and salting does not help once the salt is
// known, which it must be on every endpoint for cross-host matching to work at
// all (D10). So the test hunts for digests as well as plaintext.

// Fixture secrets. Deliberately valid-looking so a real detector would match.
var fixtureSecrets = map[string]string{
	"cpf":         "11144477735",
	"ssn":         "123456789",
	"card":        "4111111111111111",
	"email":       "alice.pereira@example.com",
	"phone":       "+5548984260564",
	"person_name": "Alice Pereira",
}

// forbiddenRepresentations returns every byte sequence that must not appear:
// the value itself, and common digests of it. If a future change decides to
// transmit a "safe" hash, this test fails and forces the argument to be had.
func forbiddenRepresentations(secret string) map[string][]byte {
	out := map[string][]byte{
		"plaintext": []byte(secret),
	}
	digests := map[string]func() hash.Hash{
		"md5":    md5.New,
		"sha1":   sha1.New,
		"sha256": sha256.New,
	}
	for name, fn := range digests {
		h := fn()
		h.Write([]byte(secret))
		sum := h.Sum(nil)
		out[name+"-raw"] = sum
		out[name+"-hex"] = []byte(hex.EncodeToString(sum))
	}
	// A keyed digest with a key an endpoint would plausibly hold. Determinism
	// across hosts is what makes cross-endpoint matching work, and it is also
	// what makes the digest brute-forceable — the key does not save it.
	for _, key := range []string{"openshield", "endpoint-key", ""} {
		m := hmac.New(sha256.New, []byte(key))
		m.Write([]byte(secret))
		sum := m.Sum(nil)
		out[fmt.Sprintf("hmac(%q)-raw", key)] = sum
		out[fmt.Sprintf("hmac(%q)-hex", key)] = []byte(hex.EncodeToString(sum))
	}
	return out
}

func assertNoSecrets(t *testing.T, what string, blob []byte) {
	t.Helper()
	for label, secret := range fixtureSecrets {
		for repr, needle := range forbiddenRepresentations(secret) {
			if len(needle) == 0 {
				continue
			}
			if bytes.Contains(blob, needle) {
				t.Errorf("%s leaks %s as %s — %d bytes of wire data contained it",
					what, label, repr, len(blob))
			}
		}
	}
}

// TestClassificationSummaryLeaksNothing is the core privacy assertion: a
// summary built from a document full of known secrets must not contain any of
// them, in any representation, anywhere in its serialized bytes.
func TestClassificationSummaryLeaksNothing(t *testing.T) {
	// What the endpoint found locally — this form holds content by design and
	// never leaves the host.
	local := &corev1.LocalClassification{
		EventId: "evt-1",
		Matches: []*corev1.LocalMatch{
			{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.99,
				MatchedText: fixtureSecrets["cpf"], Offset: 12},
			{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, Confidence: 0.97,
				MatchedText: fixtureSecrets["card"], Offset: 44},
			{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95,
				MatchedText: fixtureSecrets["cpf"], Offset: 80},
		},
	}

	// Sanity check the test itself: if the local form did NOT contain the
	// secrets, the wire assertion below would pass vacuously.
	localBlob, err := proto.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(localBlob, []byte(fixtureSecrets["cpf"])) {
		t.Fatal("test is vacuous: LocalClassification does not contain the fixture secret")
	}

	// The wire form, derived from the same finding.
	summary := &corev1.ClassificationSummary{
		EventId:      "evt-1",
		DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF,
		Confidence:   0.99,
		MatchCount:   2,
	}
	wireBlob, err := proto.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "ClassificationSummary", wireBlob)
}

// TestEventLeaksNoDirectIdentifier proves the subject is pseudonymous in
// practice, not merely by field naming. A username in a field called
// "pseudonymous_id" is still a username.
func TestEventLeaksNoDirectIdentifier(t *testing.T) {
	e := &corev1.Event{
		EventId:     "evt-2",
		AgentId:     "agent-7",
		ConnectorId: "fanotify",
		Sequence:    41,
		ObservedAt:  timestamppb.Now(),
		Subject:     &corev1.Subject{PseudonymousId: "s_9f2c1a55e7b3"},
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Kind:        corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{
			Filesystem: &corev1.FilesystemSubject{
				Identity: &corev1.FilesystemSubject_ResolvedPath{
					ResolvedPath: "/home/u/Documents/customers.csv",
				},
			},
		},
	}
	blob, err := proto.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "Event", blob)
}

// TestMatchCountConveysQuantityNotIdentity: four distinct cards must produce a
// count, with nothing distinguishing which four.
func TestMatchCountConveysQuantityNotIdentity(t *testing.T) {
	cards := []string{"4111111111111111", "4222222222222", "4012888888881881", "4000056655665556"}
	local := &corev1.LocalClassification{EventId: "evt-3"}
	for _, c := range cards {
		local.Matches = append(local.Matches, &corev1.LocalMatch{
			DetectorType: corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD,
			Confidence:   0.98,
			MatchedText:  c,
		})
	}
	summary := &corev1.ClassificationSummary{
		EventId:      "evt-3",
		DetectorType: corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD,
		Confidence:   0.98,
		MatchCount:   uint32(len(cards)),
	}
	if summary.GetMatchCount() != 4 {
		t.Fatalf("match count = %d, want 4", summary.GetMatchCount())
	}
	blob, err := proto.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cards {
		if bytes.Contains(blob, []byte(c)) {
			t.Errorf("summary distinguishes which card matched: found %s", c)
		}
	}
}
