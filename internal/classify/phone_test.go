package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func TestPhoneDetector(t *testing.T) {
	// Real formatted phone numbers are detected.
	for _, s := range []string{
		"call me at (415) 555-0132 tomorrow",
		"office: 415-555-0132",
		"ph 415.555.0132",
		"international +44 20 7946 0958 line",
		"+1 (415) 555-0132",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_PHONE) {
			t.Errorf("phone not detected in %q", s)
		}
	}

	// Bare digit runs and look-alikes must NOT trip it (the FP discipline — a phone needs
	// distinctive formatting, and the digit-count must be plausible).
	for _, s := range []string{
		"order 4155550132 shipped", // bare 10-digit run, no formatting
		"timestamp 1700000000",     // unix time
		"the code 123-45 is short", // too few digits
		"account 12.34.56 balance", // too few digits, wrong shape
		"ref +1 ----------- 9 end", // matches the +format but only 2 digits — the validator must reject
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_PHONE) {
			t.Errorf("false positive: phone detected in %q", s)
		}
	}
}

func scanFor2(t *testing.T, text string, want corev1.DetectorType) bool {
	t.Helper()
	h := scanFor(t, text, want)
	return h != nil
}
