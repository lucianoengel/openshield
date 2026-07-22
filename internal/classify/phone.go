package classify

import (
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Phone-number detector (DLP-7). A phone number has NO checksum, and a bare 10-digit run
// collides with too much (order ids, timestamps, account numbers) to be worth its false
// positives — so, like SSN, this requires DISTINCTIVE phone FORMATTING (separators, an
// international +country prefix, or parentheses around the area code) rather than any run of
// digits, and reports a low confidence to reflect the format-only evidence.
const confPhone = 0.55

type phone struct{}

// phoneRe matches common formatted phone shapes and NOT bare digit runs:
//   - E.164 international: +CC followed by 6–14 digits with optional separators
//   - North-American: (NXX) NXX-XXXX, NXX-NXX-XXXX, NXX.NXX.XXXX
//
// The separators/prefix are what make it a phone rather than an arbitrary number.
var phoneRe = regexp.MustCompile(
	`\+\d[\d\s().-]{7,17}\d` + // +country ... (7–17 more chars incl. separators)
		`|\(\d{3}\)\s*\d{3}[.\-\s]\d{4}` + // (NXX) NXX-XXXX
		`|\b\d{3}[.\-]\d{3}[.\-]\d{4}\b`) // NXX-NXX-XXXX / NXX.NXX.XXXX

func (phone) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_PHONE }
func (phone) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return string(b) }
	// validPhone counts the digits: a real phone number is 7–15 digits (E.164 max 15). This
	// rejects a formatted look-alike that is too short/long to be a phone.
	valid := func(s string) bool {
		digits := 0
		for i := 0; i < len(s); i++ {
			if s[i] >= '0' && s[i] <= '9' {
				digits++
			}
		}
		return digits >= 7 && digits <= 15
	}
	return countValid(phoneRe, text, norm, valid), confPhone
}
