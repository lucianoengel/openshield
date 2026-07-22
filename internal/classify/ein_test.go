package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DLP: the EIN detector accepts NN-NNNNNNN numbers with a valid IRS campus prefix and rejects an
// invalid prefix and the SSN grouping.
func TestEINDetector(t *testing.T) {
	for _, s := range []string{
		"EIN 12-3456789 on the W-9",
		"employer 95-1234567 filed",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_EIN) {
			t.Errorf("EIN not detected in %q", s)
		}
	}

	for _, s := range []string{
		"ref 07-1234567 note",  // prefix 07 is not an assigned IRS campus code
		"id 00-1234567 x",      // prefix 00 not assigned
		"ssn 123-45-6789 here", // SSN grouping, not EIN
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_EIN) {
			t.Errorf("false positive: EIN detected in %q", s)
		}
	}
}
