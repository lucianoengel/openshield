package classify

import (
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Confidences are fixed, documented, and never 1.0. They rank by the strength
// of the validator behind the match: a check digit is strong evidence, Luhn is
// strong, an SSA structural rule is weak (SSN has no checksum), a format-only
// email is weakest.
const (
	confCPF   = 0.95 // two check digits mod 11
	confCard  = 0.90 // Luhn
	confSSN   = 0.60 // structural only — SSN has NO checksum, so this is a weak signal by construction
	confEmail = 0.50 // format only
)

// --- CPF (Brazil) ---

type cpf struct{}

// Candidate: 11 digits, optionally punctuated as NNN.NNN.NNN-NN.
var cpfRe = regexp.MustCompile(`\d{3}\.?\d{3}\.?\d{3}-?\d{2}`)

func (cpf) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_CPF }
func (cpf) Scan(text []byte) (int, float64) {
	return countValid(cpfRe, text, stripNonDigits, validCPF), confCPF
}

// validCPF verifies the two check digits. The all-same-digit sequences
// (00000000000, 11111111111, …) satisfy the arithmetic but are documented
// invalids, so they are rejected explicitly.
func validCPF(s string) bool {
	if len(s) != 11 {
		return false
	}
	allSame := true
	for i := 1; i < 11; i++ {
		if s[i] != s[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	check := func(n int) int {
		sum := 0
		weight := n + 1
		for i := 0; i < n; i++ {
			sum += int(s[i]-'0') * (weight - i)
		}
		r := (sum * 10) % 11
		if r == 10 {
			r = 0
		}
		return r
	}
	return check(9) == int(s[9]-'0') && check(10) == int(s[10]-'0')
}

// --- Credit card ---

type creditCard struct{}

// Candidate: 13–19 digits, optionally separated by single spaces or hyphens.
var cardRe = regexp.MustCompile(`\d(?:[ -]?\d){12,18}`)

func (creditCard) Type() corev1.DetectorType {
	return corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD
}
func (creditCard) Scan(text []byte) (int, float64) {
	return countValid(cardRe, text, stripNonDigits, validLuhn), confCard
}

func validLuhn(s string) bool {
	if len(s) < 13 || len(s) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// --- SSN (US) ---

type ssn struct{}

// Hyphenated form only. Bare 9-digit runs collide with too much (order IDs,
// timestamps) to be worth their false positives, and SSN has no checksum to
// filter them.
var ssnRe = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

func (ssn) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_SSN }
func (ssn) Scan(text []byte) (int, float64) {
	return countValid(ssnRe, text, stripNonDigits, validSSNStructure), confSSN
}

// validSSNStructure applies the SSA's published structural rules. There is NO
// checksum — this is the whole reason SSN confidence is capped low.
func validSSNStructure(s string) bool {
	if len(s) != 9 {
		return false
	}
	area := s[0:3]
	group := s[3:5]
	serial := s[5:9]
	if area == "000" || area == "666" {
		return false
	}
	if area[0] == '9' { // 900–999 are not assigned
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// --- Email ---

type email struct{}

// Format only; no validator exists, so confidence is lowest.
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (email) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_EMAIL }
func (email) Scan(text []byte) (int, float64) {
	// Normalize to the lowercased whole match; email is not digits-only.
	norm := func(b []byte) string { return string(b) }
	valid := func(string) bool { return true } // the regex IS the validator
	return countValid(emailRe, text, norm, valid), confEmail
}

// --- US bank routing number (ABA) ---

// confABA sits above the checksumless structural detectors and below the two-check-digit
// schemes: an ABA number has one weighted mod-10 checksum plus a constrained leading range,
// which filters the great majority of random 9-digit runs but not as strongly as CPF's two
// check digits.
const confABA = 0.75

type abaRouting struct{}

// Candidate: a bare 9-digit run. The word boundaries keep it from matching inside a longer
// digit run (a 10-digit phone, a 16-digit card), and the checksum below does the real filtering
// — a bare 9-digit run alone is far too common to report.
var abaRe = regexp.MustCompile(`\b\d{9}\b`)

func (abaRouting) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_ABA_ROUTING }
func (abaRouting) Scan(text []byte) (int, float64) {
	return countValid(abaRe, text, stripNonDigits, validABA), confABA
}

// validABA checks the Federal Reserve leading-digit range AND the ABA weighted mod-10 checksum.
// Both are required: the checksum alone passes ~1 in 10 random 9-digit runs, and the leading
// range alone is far too weak, so together they make a bare 9-digit run reportable.
func validABA(s string) bool {
	if len(s) != 9 {
		return false
	}
	// Routing symbol (first two digits) must be an assigned Federal Reserve range:
	// 00–12 (government / FRB), 21–32, 61–72 (thrift/electronic), 80 (traveler's cheque).
	lead := int(s[0]-'0')*10 + int(s[1]-'0')
	inRange := lead <= 12 || (lead >= 21 && lead <= 32) || (lead >= 61 && lead <= 72) || lead == 80
	if !inRange {
		return false
	}
	d := func(i int) int { return int(s[i] - '0') }
	sum := 3*(d(0)+d(3)+d(6)) + 7*(d(1)+d(4)+d(7)) + (d(2) + d(5) + d(8))
	return sum%10 == 0
}

// --- Canadian Social Insurance Number (SIN) ---

// confSIN: a Luhn checksum over a distinctively grouped number is strong, low-FP evidence —
// comparable to the credit-card Luhn, a touch lower because the number is shorter (9 vs 13–19
// digits, so a chance Luhn pass is likelier).
const confSIN = 0.85

type caSIN struct{}

// Candidate: the conventional grouped form NNN-NNN-NNN (hyphen or space separated). A bare
// 9-digit SIN is deliberately NOT matched — like a bare SSN, it collides with too much; the
// grouping is what makes it a SIN rather than an arbitrary number, and the Luhn does the rest.
var caSINRe = regexp.MustCompile(`\b\d{3}[ -]\d{3}[ -]\d{3}\b`)

func (caSIN) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_CA_SIN }
func (caSIN) Scan(text []byte) (int, float64) {
	return countValid(caSINRe, text, stripNonDigits, validSIN), confSIN
}

// validSIN applies the Luhn checksum over the 9 digits (the published SIN validation).
func validSIN(s string) bool {
	if len(s) != 9 {
		return false
	}
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// --- US National Provider Identifier (NPI) ---

// confNPI: a real check-digit scheme (Luhn over the 80840-prefixed number) plus the leading
// 1-or-2 constraint — strong, though a bare 10-digit run is common enough (it collides with
// phone numbers) that this sits a touch below the card Luhn.
const confNPI = 0.80

type npi struct{}

// Candidate: a bare 10-digit run. The word boundaries keep it out of longer runs; the leading
// digit and Luhn below do the filtering.
var npiRe = regexp.MustCompile(`\b\d{10}\b`)

func (npi) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_NPI }
func (npi) Scan(text []byte) (int, float64) {
	return countValid(npiRe, text, stripNonDigits, validNPI), confNPI
}

// validNPI checks the NPI's leading digit (every NPI begins with 1 or 2) AND the Luhn checksum
// over the number prefixed with the fixed issuer id 80840 (the published NPI check). Both are
// required: the prefix constraint eliminates most non-NPI 10-digit runs the checksum would pass.
func validNPI(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[0] != '1' && s[0] != '2' {
		return false
	}
	full := "80840" + s
	sum := 0
	double := false
	for i := len(full) - 1; i >= 0; i-- {
		d := int(full[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// --- UK NHS number ---

// confNHS: a weighted mod-11 check digit over the distinctive 3-3-4 spaced grouping — strong,
// low-FP evidence comparable to the other grouped-checksum PII.
const confNHS = 0.85

type ukNHS struct{}

// Candidate: the conventional 3-3-4 SPACE-separated grouping. Space (not hyphen) is deliberate —
// it is the canonical NHS presentation and avoids overlap with the hyphen/dot phone format.
var nhsRe = regexp.MustCompile(`\b\d{3} \d{3} \d{4}\b`)

func (ukNHS) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_UK_NHS }
func (ukNHS) Scan(text []byte) (int, float64) {
	return countValid(nhsRe, text, stripNonDigits, validNHS), confNHS
}

// validNHS applies the NHS weighted mod-11 check: weights 10..2 over the first nine digits, the
// tenth is the check digit. A remainder giving a check of 10 marks an INVALID number (no valid
// NHS number has that check), and 11 maps to 0.
func validNHS(s string) bool {
	if len(s) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(s[i]-'0') * (10 - i)
	}
	check := 11 - (sum % 11)
	if check == 11 {
		check = 0
	}
	if check == 10 {
		return false // not a valid check digit → not an NHS number
	}
	return check == int(s[9]-'0')
}

// --- US Employer Identification Number (EIN) ---

// confEIN: a distinctive 2-7 hyphenated format plus the IRS campus-prefix whitelist, but NO
// checksum — moderate evidence, on par with SSN (structural only).
const confEIN = 0.60

type ein struct{}

// Candidate: the conventional NN-NNNNNNN grouping (distinct from the SSN 3-2-4 shape).
var einRe = regexp.MustCompile(`\b\d{2}-\d{7}\b`)

// einPrefixes is the set of IRS-assigned EIN campus prefixes (the first two digits). A number
// whose prefix is not on this published list is not a validly-issued EIN.
var einPrefixes = map[string]struct{}{}

func init() {
	for _, p := range []string{
		"01", "02", "03", "04", "05", "06", "10", "11", "12", "13", "14", "15", "16",
		"20", "21", "22", "23", "24", "25", "26", "27", "30", "31", "32", "33", "34",
		"35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47",
		"48", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61",
		"62", "63", "64", "65", "66", "67", "68", "71", "72", "73", "74", "75", "76",
		"77", "80", "81", "82", "83", "84", "85", "86", "87", "88", "90", "91", "92",
		"93", "94", "95", "98", "99",
	} {
		einPrefixes[p] = struct{}{}
	}
}

func (ein) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_EIN }
func (ein) Scan(text []byte) (int, float64) {
	// The candidate keeps the hyphen; validate the prefix on the whole match, and de-dup on the
	// digits so a repeated fixture does not inflate the count.
	norm := func(b []byte) string { return string(b) }
	valid := func(s string) bool {
		if len(s) < 2 {
			return false
		}
		_, ok := einPrefixes[s[:2]]
		return ok
	}
	return countValid(einRe, text, norm, valid), confEIN
}
