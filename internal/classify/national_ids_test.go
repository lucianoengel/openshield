package classify_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func classifyStr(t *testing.T, s string) []*corev1.DetectorHit {
	t.Helper()
	hits, err := classify.New().Classify(context.Background(), strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// TestAadhaarDetection (DLP-7): a Verhoeff-valid Aadhaar (spaced or bare) is detected; a
// checksum-tampered 12-digit number is not counted.
//
// Mutation: if verhoeffValid always returned true, the tampered number would be counted → the
// "not detected" assertion FAILs.
func TestAadhaarDetection(t *testing.T) {
	// 234567890124 is Verhoeff-valid; the spaced 4-4-4 form is the conventional presentation.
	if !hasType(classifyStr(t, "Aadhaar: 2345 6789 0124 on record"), corev1.DetectorType_DETECTOR_TYPE_AADHAAR) {
		t.Error("a valid spaced Aadhaar was not detected")
	}
	if !hasType(classifyStr(t, "id 234567890124 leaked"), corev1.DetectorType_DETECTOR_TYPE_AADHAAR) {
		t.Error("a valid bare Aadhaar was not detected")
	}
	// Tamper the check digit (…124 → …120): Verhoeff fails → not counted.
	if hasType(classifyStr(t, "id 234567890120 here"), corev1.DetectorType_DETECTOR_TYPE_AADHAAR) {
		t.Error("a checksum-invalid Aadhaar candidate was counted — the Verhoeff check is not applied")
	}
	// A number starting with 0/1 is never Aadhaar (first-digit constraint).
	if hasType(classifyStr(t, "id 134567890124 here"), corev1.DetectorType_DETECTOR_TYPE_AADHAAR) {
		t.Error("a 12-digit number starting with 1 was counted as Aadhaar")
	}
}

// TestUKNINODetection (DLP-7): a NINO near a National-Insurance keyword is detected; a bare NINO with
// no context is not fired (reusing the contextNear primitive, like passport/DL).
//
// Mutation: if ukNINO scanned structurally (no contextNear), the bare NINO would be counted → the
// "no context" assertion FAILs.
func TestUKNINODetection(t *testing.T) {
	if !hasType(classifyStr(t, "National Insurance number AB 12 34 56 C"), corev1.DetectorType_DETECTOR_TYPE_UK_NINO) {
		t.Error("a NINO near its keyword was not detected")
	}
	if !hasType(classifyStr(t, "NINO: JG123456A"), corev1.DetectorType_DETECTOR_TYPE_UK_NINO) {
		t.Error("a compact NINO near the NINO keyword was not detected")
	}
	// No National-Insurance context → not fired (the DLP-7 precision trade).
	if hasType(classifyStr(t, "reference AB123456C in the ticket"), corev1.DetectorType_DETECTOR_TYPE_UK_NINO) {
		t.Error("a bare NINO with no context keyword was counted — it must be context-gated")
	}
	// An excluded prefix (DF…) near the keyword is still rejected by the prefix rules.
	if hasType(classifyStr(t, "National Insurance DF123456C"), corev1.DetectorType_DETECTOR_TYPE_UK_NINO) {
		t.Error("a NINO with an excluded prefix (DF) was counted — the prefix rules are not applied")
	}
}
