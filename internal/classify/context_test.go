package classify

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func TestPassportContextGated(t *testing.T) {
	det := passport{}

	// Near the keyword → detected.
	if n, _ := det.Scan([]byte("Passport No: 123456789 issued 2020")); n != 1 {
		t.Fatalf("passport near keyword = %d, want 1", n)
	}
	if n, _ := det.Scan([]byte("her 123456789 (passport) is valid")); n != 1 {
		t.Fatalf("passport with trailing keyword = %d, want 1", n)
	}
	// The SAME number with NO keyword nearby → not detected (the context precision).
	if n, _ := det.Scan([]byte("order number 123456789 shipped today")); n != 0 {
		t.Fatalf("bare 9-digit number = %d, want 0 (no passport keyword)", n)
	}
	// Keyword alone, no value → not detected.
	if n, _ := det.Scan([]byte("please bring your passport to the desk")); n != 0 {
		t.Fatalf("passport keyword with no value = %d, want 0", n)
	}
	// De-dup: the same value twice near keywords counts once.
	if n, _ := det.Scan([]byte("passport 123456789 ... passport 123456789")); n != 1 {
		t.Fatalf("repeated same passport = %d, want 1 (de-duped)", n)
	}
}

// TestPassportDistantKeyword proves the proximity window is bounded: a passport
// keyword far from the value does not qualify it (else the window would be useless).
func TestPassportDistantKeyword(t *testing.T) {
	pad := make([]byte, 200)
	for i := range pad {
		pad[i] = 'x'
	}
	text := append([]byte("passport "), pad...)
	text = append(text, []byte(" 123456789")...)
	if n, _ := (passport{}).Scan(text); n != 0 {
		t.Fatalf("a distant keyword qualified the value (%d) — the window is too large", n)
	}
}

func TestDriversLicenseContextGated(t *testing.T) {
	det := driversLicense{}
	if n, _ := det.Scan([]byte("Driver's License: D1234567 exp 2027")); n != 1 {
		t.Fatalf("DL near keyword = %d, want 1", n)
	}
	if n, _ := det.Scan([]byte("DL # X9988776")); n != 1 {
		t.Fatalf("DL near 'DL #' = %d, want 1", n)
	}
	// Same value, no license keyword → not detected (the pattern is too generic alone).
	if n, _ := det.Scan([]byte("product code D1234567 in stock")); n != 0 {
		t.Fatalf("bare alphanumeric = %d, want 0 (no license keyword)", n)
	}
}

// TestDriversLicenseIgnoresAllCapsWords (R34-11): an all-caps sentence near the
// keyword must not over-count ordinary words as license values — only the value
// with a digit counts.
func TestDriversLicenseIgnoresAllCapsWords(t *testing.T) {
	det := driversLicense{}
	// "DRIVER", "LICENSE", "NUMBER", "EXPIRES", "SOON" are all-caps words (no digit);
	// only D1234567 is a real license value.
	n, _ := det.Scan([]byte("DRIVER LICENSE NUMBER D1234567 EXPIRES SOON"))
	if n != 1 {
		t.Fatalf("all-caps sentence = %d license values, want exactly 1 (the one with a digit) — R34-11", n)
	}
	// An all-caps line with the keyword but NO digit-bearing value → 0.
	if n, _ := det.Scan([]byte("PLEASE BRING YOUR DRIVER LICENSE TODAY")); n != 0 {
		t.Fatalf("all-caps line with no license number = %d, want 0", n)
	}
}

func TestContextDetectorsThroughClassifier(t *testing.T) {
	c := New()
	hits, err := c.Classify(context.Background(), strings.NewReader("Passport Number 987654321 on file"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasHit(hits, corev1.DetectorType_DETECTOR_TYPE_PASSPORT) {
		t.Fatal("classifier did not report a passport near its keyword")
	}
	// A bare number without the keyword → no passport hit from the classifier.
	h2, _ := c.Classify(context.Background(), strings.NewReader("invoice 987654321 total due"))
	if hasHit(h2, corev1.DetectorType_DETECTOR_TYPE_PASSPORT) {
		t.Fatal("classifier reported a passport for a bare number (no context)")
	}
}
