package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func TestIBANDetector(t *testing.T) {
	// Real, mod-97-valid IBANs (including the printed space-grouped form and a BBAN with
	// letters), each must be detected.
	valid := []string{
		"DE89370400440532013000",
		"GB82WEST12345698765432",
		"FR1420041010050500013M02606",
		"payment to DE89 3704 0044 0532 0130 00 today",
	}
	for _, s := range valid {
		if !hasType(classifyBytes(t, []byte(s)), corev1.DetectorType_DETECTOR_TYPE_IBAN) {
			t.Errorf("valid IBAN not detected in %q", s)
		}
	}

	// Look-alikes: a wrong check digit (fails mod-97), a wrong length for the country, and
	// an unknown country code must all read clean.
	invalid := []string{
		"DE89370400440532013001", // last digit changed → mod-97 fails
		"DE8937040044053201300",  // one digit short → wrong length for DE
		"ZZ8937040044053201300",  // unknown country code
		"GB111234567890123456",   // passes mod-97 but WRONG length for GB (22) → the length guard must reject it
		"the code AB12CDEF is short",
	}
	for _, s := range invalid {
		if hasType(classifyBytes(t, []byte(s)), corev1.DetectorType_DETECTOR_TYPE_IBAN) {
			t.Errorf("invalid IBAN-shaped string was detected (false positive): %q", s)
		}
	}
}

func TestHealthDataDetector(t *testing.T) {
	// Three or more distinct health terms → a (low-confidence) hit.
	strong := "Patient record: diagnosis hypertension, prescription lisinopril, blood pressure 150/95."
	h := scanFor(t, strong, corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA)
	if h == nil {
		t.Error("multi-term health text was not detected")
	} else if h.GetConfidence() > 0.7 {
		t.Errorf("health confidence %v too high — a validator-free detector must be conservative", h.GetConfidence())
	}

	// A single medical word in isolation is too weak to fire (FP discipline).
	if hasType(classifyBytes(t, []byte("the diagnosis was correct and everyone agreed")), corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA) {
		t.Error("a single health term fired the detector — it must require multiple distinct terms")
	}
}
