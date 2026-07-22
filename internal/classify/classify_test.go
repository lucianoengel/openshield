package classify_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Verified vectors. CPF 111.444.777-35 has valid check digits; the card and SSN
// are standard test values (Luhn-valid, structurally valid).
const (
	validCPF    = "111.444.777-35"
	invalidCPF  = "111.444.777-36" // last check digit wrong
	validCard   = "4242 4242 4242 4242"
	invalidCard = "4242 4242 4242 4241" // fails Luhn
	validSSN    = "078-05-1120"
	validEmail  = "alice@example.com"
)

func classifyString(t *testing.T, s string) []*corev1.DetectorHit {
	t.Helper()
	hits, err := classify.New().Classify(context.Background(), strings.NewReader(s))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	return hits
}

func hitFor(hits []*corev1.DetectorHit, dt corev1.DetectorType) *corev1.DetectorHit {
	for _, h := range hits {
		if h.GetDetectorType() == dt {
			return h
		}
	}
	return nil
}

// Task 3.1. Each seeded type is detected with the right count.
func TestDetectsSeededPII(t *testing.T) {
	doc := "customer " + validCPF + " paid with card " + validCard +
		" ssn " + validSSN + " contact " + validEmail
	hits := classifyString(t, doc)

	for _, dt := range []corev1.DetectorType{
		corev1.DetectorType_DETECTOR_TYPE_CPF,
		corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD,
		corev1.DetectorType_DETECTOR_TYPE_SSN,
		corev1.DetectorType_DETECTOR_TYPE_EMAIL,
	} {
		h := hitFor(hits, dt)
		if h == nil {
			t.Errorf("%s not detected", dt)
			continue
		}
		if h.GetCount() < 1 {
			t.Errorf("%s count = %d, want >= 1", dt, h.GetCount())
		}
		if h.GetConfidence() <= 0 || h.GetConfidence() >= 1 {
			t.Errorf("%s confidence = %v, want in (0,1)", dt, h.GetConfidence())
		}
	}
}

// Task 3.2. Format without a valid checksum must NOT hit — this proves the
// validator actually runs rather than the regex alone deciding.
func TestFormatWithoutChecksumIsRejected(t *testing.T) {
	hits := classifyString(t, "cpf "+invalidCPF+" card "+invalidCard)
	if h := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_CPF); h != nil {
		t.Errorf("a CPF with a wrong check digit was reported — the validator did not run")
	}
	if h := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD); h != nil {
		t.Errorf("a Luhn-invalid number was reported as a card — the validator did not run")
	}
}

// Task 3.3. Published-vector table for the checksum validators.
func TestChecksumVectors(t *testing.T) {
	cases := []struct {
		in   string
		dt   corev1.DetectorType
		want bool
	}{
		{"111.444.777-35", corev1.DetectorType_DETECTOR_TYPE_CPF, true},
		{"111.444.777-00", corev1.DetectorType_DETECTOR_TYPE_CPF, false},
		{"000.000.000-00", corev1.DetectorType_DETECTOR_TYPE_CPF, false}, // all-same, arithmetic-valid but a documented invalid
		{"4242424242424242", corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, true},
		{"4111111111111111", corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, true},
		{"1234567890123456", corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, false},
	}
	for _, c := range cases {
		hits := classifyString(t, "value "+c.in+" end")
		got := hitFor(hits, c.dt) != nil
		if got != c.want {
			t.Errorf("%q detected=%v, want %v", c.in, got, c.want)
		}
	}
}

// Task 3.4. SSN is a weaker signal than CPF, and the numbers say so.
func TestSSNIsAWeakerSignalThanCPF(t *testing.T) {
	hits := classifyString(t, "cpf "+validCPF+" ssn "+validSSN)
	cpfHit := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_CPF)
	ssnHit := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_SSN)
	if cpfHit == nil || ssnHit == nil {
		t.Fatal("expected both a CPF and an SSN hit")
	}
	if !(ssnHit.GetConfidence() < cpfHit.GetConfidence()) {
		t.Errorf("SSN confidence %v not lower than CPF %v — SSN has no checksum and "+
			"must report as the weaker signal it is", ssnHit.GetConfidence(), cpfHit.GetConfidence())
	}
}

// Task 4.1. The privacy invariant, enforced by grepping the WIRE bytes. A future
// field that carried matched content would fail here, which is the point — a
// negative property in prose rots, a test does not.
func TestNoSeedValueOnTheWire(t *testing.T) {
	seeds := []string{validCPF, "11144477735", validCard, "4242424242424242", validSSN, "078051120", validEmail}
	doc := strings.Join(seeds, " ")
	hits := classifyString(t, doc)
	if len(hits) == 0 {
		t.Fatal("nothing detected; the test would be vacuous")
	}
	var wire bytes.Buffer
	for _, h := range hits {
		b, err := proto.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(b)
	}
	blob := wire.Bytes()
	for _, seed := range seeds {
		for _, form := range []string{seed, strings.ReplaceAll(strings.ReplaceAll(seed, ".", ""), "-", "")} {
			if bytes.Contains(blob, []byte(form)) {
				t.Errorf("seeded value %q appears in the serialized hits — the classifier "+
					"is leaking content it must never emit", form)
			}
		}
	}
}

// Task 4.2. The count/confidence carry no per-value signal: different values,
// same counts, identical output.
func TestCountIsNotADigest(t *testing.T) {
	a := classifyString(t, "111.444.777-35 and 4242424242424242")
	b := classifyString(t, "295.379.955-93 and 4111111111111111")
	if len(a) != len(b) {
		t.Fatalf("different hit counts: %d vs %d", len(a), len(b))
	}
	norm := func(hs []*corev1.DetectorHit) map[corev1.DetectorType]string {
		m := map[corev1.DetectorType]string{}
		for _, h := range hs {
			b, _ := proto.Marshal(h)
			m[h.GetDetectorType()] = string(b)
		}
		return m
	}
	ma, mb := norm(a), norm(b)
	for dt, va := range ma {
		if mb[dt] != va {
			t.Errorf("%s: hits differ between documents with equal counts — a per-value "+
				"signal leaked into the count or confidence", dt)
		}
	}
}

// Task 5.1. RE2 is linear-time; a backtracking engine would blow up on this. If
// a future change swapped in a backtracking matcher, this test would hang or
// blow the deadline rather than a production incident finding it.
func TestNoCatastrophicBacktracking(t *testing.T) {
	// A long run of digits interrupted so no full match completes — the shape
	// that induces catastrophic backtracking in a naive engine.
	adversarial := strings.Repeat("4242424242424242 nope ", 20000)
	done := make(chan struct{})
	go func() {
		_, _ = classify.New().Classify(context.Background(), strings.NewReader(adversarial))
		close(done)
	}()
	// The deadline only has to separate linear from exponential. RE2 scans this
	// ~440 KB in well under a second; a backtracking engine would need longer than
	// the age of the universe. The ceiling is set generously (not tight) because
	// the discriminating gap is astronomical and CI runs this under -race on shared
	// runners, where the linear pass alone can take several seconds — a tight bound
	// there flakes without adding any signal (it took 3s under -race locally).
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("classification did not finish in 30s on adversarial input — a " +
			"backtracking engine is a fail-open (D17) primitive")
	}
}

// An error is never a clean result.
func TestReadErrorIsNotEmptyHits(t *testing.T) {
	_, err := classify.New().Classify(context.Background(), failingReader{})
	if err == nil {
		t.Fatal("a read failure produced no error — 'did not scan' would read as 'found nothing'")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
