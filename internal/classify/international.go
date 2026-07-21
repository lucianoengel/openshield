package classify

import (
	"regexp"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// International PII detectors (Phase D2 remainder). IBAN carries a mod-97 checksum, so it
// is a strong, low-FP detector like CPF; health-data is keyword/dictionary evidence with
// NO checksum, so — like SSN and email — its confidence is capped low and it is deliberately
// conservative (requires several distinct terms) to keep the false-positive rate down.
const (
	confIBAN   = 0.93 // ISO 7064 mod-97-10 check
	confHealth = 0.55 // dictionary only, no validator — weak by construction
)

// --- IBAN ---

type iban struct{}

// IBAN: two-letter country + two check digits + up to 30 alphanumerics, optionally
// written in space-separated groups of four (the printed convention). The regex is the
// candidate; validIBAN (mod-97) is the real filter, so a random country-code-shaped
// string does not trip it. Spaces are stripped in normalization before validation.
var ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b`)

func (iban) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_IBAN }
func (iban) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return strings.ReplaceAll(string(b), " ", "") }
	return countValid(ibanRe, text, norm, validIBAN), confIBAN
}

// validIBAN applies the ISO 7064 mod-97-10 check: move the first four chars to the end,
// map letters to 10–35, and require the resulting number ≡ 1 (mod 97). It also enforces
// the country's fixed total length, rejecting truncated or padded look-alikes.
func validIBAN(s string) bool {
	s = strings.ToUpper(s)
	if n, ok := ibanLen[s[:2]]; !ok || len(s) != n {
		return false
	}
	rearranged := s[4:] + s[:4]
	// Compute mod 97 over the letter-expanded digit string without building a big int.
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			// A→10 … Z→35, each a two-digit contribution.
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ibanLen is the fixed IBAN length per country (a representative subset — the common
// SEPA/EU set plus a few others). An unknown country code is rejected: without the fixed
// length a mod-97 pass alone would admit malformed strings.
var ibanLen = map[string]int{
	"DE": 22, "FR": 27, "GB": 22, "ES": 24, "IT": 27, "NL": 18, "BE": 16,
	"CH": 21, "AT": 20, "PT": 25, "IE": 22, "PL": 28, "SE": 24, "NO": 15,
	"DK": 18, "FI": 18, "BR": 29, "LU": 20, "GR": 27, "CZ": 24,
}

// --- Health data (keyword/dictionary) ---

type healthData struct{}

// Health terms — a small, high-signal dictionary. NO checksum exists, so this requires
// MULTIPLE distinct terms to fire (one word like "diagnosis" in isolation is too common),
// and reports low confidence. It is corroborating evidence for a policy, not a strong hit
// on its own — the honest treatment of a validator-free detector (cf. SSN/email).
var healthTerms = []string{
	"diagnosis", "prognosis", "prescription", "medication", "icd-10", "icd10",
	"blood pressure", "cholesterol", "hemoglobin", "mri scan", "ct scan",
	"chemotherapy", "hiv positive", "medical record", "patient id", "treatment plan",
}

func (healthData) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_HEALTH_DATA }
func (healthData) Scan(text []byte) (int, float64) {
	lower := strings.ToLower(string(text))
	distinct := 0
	for _, term := range healthTerms {
		if strings.Contains(lower, term) {
			distinct++
		}
	}
	// Require at least three distinct terms — a single medical word is too weak to report.
	if distinct < 3 {
		return 0, confHealth
	}
	return 1, confHealth
}
