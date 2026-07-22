package classify

import (
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// contextNear counts distinct values matched by valueRe that have a keyword
// (keywordRe) within `window` bytes before or after the value in text — the DLP-7
// precision mechanism for weak-format identifiers with no checksum. A value far
// from any keyword never fires, so a bare number does not flood. Counts de-dup on
// the normalized value (lowercased digits/letters) so a repeated fixture does not
// inflate the count, and no matched value crosses the boundary (D10).
func contextNear(valueRe, keywordRe *regexp.Regexp, window int, text []byte) int {
	seen := map[string]struct{}{}
	for _, loc := range valueRe.FindAllIndex(text, -1) {
		start, end := loc[0], loc[1]
		lo := start - window
		if lo < 0 {
			lo = 0
		}
		hi := end + window
		if hi > len(text) {
			hi = len(text)
		}
		// A keyword must appear in the window, but NOT be the value itself — check
		// the region before and after the value, so the value's own bytes can't
		// masquerade as context.
		before := keywordRe.Match(text[lo:start])
		after := keywordRe.Match(text[end:hi])
		if !before && !after {
			continue
		}
		seen[normContextValue(text[start:end])] = struct{}{}
	}
	return len(seen)
}

// normContextValue lowercases and keeps only alphanumerics — the de-dup key.
func normContextValue(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		}
	}
	return string(out)
}

// contextWindow is the byte proximity between a value and its context keyword.
const contextWindow = 40

var (
	passportValueRe = regexp.MustCompile(`\b[A-Z]?\d{8,9}\b`)
	passportKeyRe   = regexp.MustCompile(`(?i)passport`)

	dlValueRe = regexp.MustCompile(`\b[A-Z0-9]{5,20}\b`)
	dlKeyRe   = regexp.MustCompile(`(?i)driver'?s?\s+licen[sc]e|\bdl\s*(no|number|#)`)
)

// confContext is the moderate confidence of a context-gated, checksumless match:
// stronger than bare structural (the keyword filters most FPs), weaker than a
// checksum — a signal a policy weighs, never certainty (D4).
const confContext = 0.60

// passport detects a passport number only near a "passport" keyword (DLP-7).
type passport struct{}

func (passport) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_PASSPORT }
func (passport) Scan(text []byte) (int, float64) {
	return contextNear(passportValueRe, passportKeyRe, contextWindow, text), confContext
}

// driversLicense detects a driver's license only near a license context keyword.
// State-variable format, so context-REQUIRED (DLP-7).
type driversLicense struct{}

func (driversLicense) Type() corev1.DetectorType {
	return corev1.DetectorType_DETECTOR_TYPE_DRIVERS_LICENSE
}
func (driversLicense) Scan(text []byte) (int, float64) {
	return contextNear(dlValueRe, dlKeyRe, contextWindow, text), confContext
}
