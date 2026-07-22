package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DLP: the UK NHS detector accepts grouped, mod-11-valid numbers and rejects a wrong check digit
// and a bare (ungrouped) run.
func TestUKNHSDetector(t *testing.T) {
	// Grouped, mod-11-valid NHS numbers (943 476 5919 verified; 943 476 5927 verified).
	for _, s := range []string{
		"patient 943 476 5919 admitted",
		"NHS: 943 476 5927",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_UK_NHS) {
			t.Errorf("NHS number not detected in %q", s)
		}
	}

	for _, s := range []string{
		"ref 943 476 5910 note",   // wrong check digit (should be 9)
		"id 943 476 5911 x",       // wrong check digit
		"bare 9434765919 nogroup", // valid digits but ungrouped → not a candidate
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_UK_NHS) {
			t.Errorf("false positive: NHS detected in %q", s)
		}
	}
}
