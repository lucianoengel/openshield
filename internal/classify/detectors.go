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
