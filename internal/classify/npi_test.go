package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DLP: the NPI detector accepts a valid 10-digit NPI (leading 1/2 + 80840-prefixed Luhn) and
// rejects a Luhn-off-by-one and a checksum-valid-but-wrong-leading-digit number — both guards
// are load-bearing.
func TestNPIDetector(t *testing.T) {
	// 1234567893 is a valid NPI (80840-prefixed Luhn == 0, leads with 1).
	for _, s := range []string{
		"provider NPI 1234567893 billed",
		"npi:1234567893",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_NPI) {
			t.Errorf("NPI not detected in %q", s)
		}
	}

	for _, s := range []string{
		"claim 1234567894 denied",  // last digit +1 → Luhn fails (leads with 1)
		"code 3000000000 archived", // passes 80840-prefixed Luhn (sum 30) but leads with 3 (no NPI does)
		"order 4155550132 shipped", // a bare 10-digit run, leads with 4
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_NPI) {
			t.Errorf("false positive: NPI detected in %q", s)
		}
	}
}
