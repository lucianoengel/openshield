package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DLP: the Canadian SIN detector accepts grouped, Luhn-valid numbers and rejects a
// Luhn-off-by-one, a grouped-but-invalid number, and a bare (ungrouped) 9-digit run.
func TestCanadianSINDetector(t *testing.T) {
	// Grouped, Luhn-valid SINs (hyphen and space forms).
	for _, s := range []string{
		"SIN 046-454-286 on file",
		"employee 193-456-787 payroll",
		"sin: 046 454 286",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_CA_SIN) {
			t.Errorf("SIN not detected in %q", s)
		}
	}

	for _, s := range []string{
		"ref 046-454-287 note",     // last digit +1 → Luhn fails
		"code 123-456-789 here",    // well-grouped but Luhn-invalid
		"bare 046454286 ungrouped", // valid digits but NOT grouped → not a SIN candidate
		"ssn 046-45-4286 us",       // SSN grouping, not SIN grouping
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_CA_SIN) {
			t.Errorf("false positive: SIN detected in %q", s)
		}
	}
}
