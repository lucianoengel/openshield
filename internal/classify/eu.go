package classify

import (
	"regexp"
	"strconv"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// EUROPEAN NATIONAL IDENTIFIERS (DLP-10).
//
// The detector set could find a Brazilian CPF, a US SSN and an Indian Aadhaar and nothing a French or
// Spanish deployment would actually be holding — which is most of the GDPR-relevant personal data in
// Europe. These are the two whose check algorithms could be anchored to PUBLISHED worked examples, and
// that is the whole selection criterion: a national-ID detector whose checksum is subtly wrong produces
// false positives AND false negatives, and the deployment that suffers is the one that trusted it.
//
// ITALY'S CODICE FISCALE IS DELIBERATELY ABSENT. Its check letter comes from two 36-entry tables, and
// the tables I could reconstruct matched exactly one published example. One vector over a 36-entry table
// does not rule out a single wrong entry, which would misclassify a narrow, unpredictable slice of real
// identifiers forever. It is a follow-up with a properly sourced vector, not a guess shipped now.

// --- Spain: DNI and NIE ---

// confESDNI: context-gated, so it carries the same confidence as the other context-required
// identifiers rather than the checksummed ones — the check contributes, but the keyword is what makes
// the hit trustworthy.
const confESDNI = confContext

// dniLetters is the official check-letter table, indexed by the number mod 23.
const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// esDNIValueRe matches a DNI (8 digits + letter) or a NIE (X/Y/Z + 7 digits + letter). The separator is
// optional because both are written with and without one.
var esDNIValueRe = regexp.MustCompile(`\b(?:[XYZxyz][ -]?\d{7}|\d{8})[ -]?[A-Za-z]\b`)

// esDNIKeyRe is the context this detector REQUIRES.
//
// WHY IT IS GATED AT ALL, when it has a real checksum: the check is a single letter chosen from 23, so
// roughly one in twenty-three arbitrary "8 digits then a letter" tokens passes it. That shape occurs
// constantly — order numbers, part codes, hashes broken across a line — so an unguarded detector would
// report a few percent of them forever, and a detector an operator learns to ignore protects nothing.
// The same reasoning already gates passports and driver's licences here.
var esDNIKeyRe = regexp.MustCompile(`(?i)\b(dni|nie|documento\s+nacional|documento\s+de\s+identidad|nif)\b`)

type esDNI struct{}

func (esDNI) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_ES_DNI }

func (esDNI) Scan(text []byte) (int, float64) {
	return contextNear(esDNIValueRe, esDNIKeyRe, contextWindow, text, esDNIValid), confESDNI
}

// esDNIValid checks the mod-23 letter.
//
// Anchored to the published worked examples 12345678Z (DNI) and X1234567L (NIE), both of which this
// reproduces — see the test.
func esDNIValid(s string) bool {
	c := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, s))
	if len(c) != 9 {
		return false
	}
	letter := c[8]
	if letter < 'A' || letter > 'Z' {
		return false
	}
	digits := c[:8]
	// A NIE replaces the leading letter with a digit: X→0, Y→1, Z→2. Getting this substitution wrong
	// would make every NIE fail while every DNI passed — a whole population of identifiers invisible,
	// with nothing to indicate it.
	switch digits[0] {
	case 'X':
		digits = "0" + digits[1:]
	case 'Y':
		digits = "1" + digits[1:]
	case 'Z':
		digits = "2" + digits[1:]
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return false
	}
	return dniLetters[n%23] == letter
}

// --- France: NIR (numéro de sécurité sociale) ---

// confFRNIR: a 1-in-97 check over a 15-digit shape that is rare by accident, so this stands on its own
// like the other checksummed national IDs.
const confFRNIR = 0.85

// frNIRValueRe matches the 15-digit NIR, with or without the conventional grouping spaces.
//
// The leading digit is 1 or 2 (male/female). The 3/4/7/8 temporary-registration prefixes are NOT
// matched: they are rare, and widening the pattern to catch them would triple the number of 15-digit
// runs entering the checksum for a population most deployments will never hold.
var frNIRValueRe = regexp.MustCompile(`\b[12][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b`)

type frNIR struct{}

func (frNIR) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_FR_NIR }

func (frNIR) Scan(text []byte) (int, float64) {
	return countValid(frNIRValueRe, text, stripNonDigits, frNIRValid), confFRNIR
}

// frNIRValid checks the two-digit key: 97 minus the 13-digit number modulo 97.
//
// Anchored to the published worked example 2 69 05 49 588 157 80, whose key this reproduces.
//
// CORSICA IS A STATED LIMIT. Departments 2A and 2B make the 13-digit part alphanumeric, and the
// algorithm substitutes 19 and 18 for them. This reader is digits-only, so a Corsican NIR is not
// detected — a FALSE NEGATIVE, named here rather than left for someone to discover. It is the safe
// direction to be wrong in for a detector, and it is not the same thing as being right.
func frNIRValid(s string) bool {
	if len(s) != 15 {
		return false
	}
	body, err := strconv.ParseInt(s[:13], 10, 64)
	if err != nil {
		return false
	}
	key, err := strconv.Atoi(s[13:])
	if err != nil {
		return false
	}
	// A key of 0 is not producible: 97 - (n mod 97) lands in 1..97, and 97 is written as 97.
	return key == int(97-(body%97))
}
