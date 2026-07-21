package classify

import (
	"encoding/base64"
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Secrets / credentials detectors (Phase D2). Unlike PII these are STRUCTURAL:
// a PEM block, a prefixed cloud key, a decodable JWT are unambiguous artifacts,
// so a validated hit is strong, low-false-positive evidence — the confidences
// here are high, and a leaked key is the ideal candidate for an inline block
// (D94). Each detector pairs a candidate regex with a real validator (the CPF /
// Luhn discipline), never a bare regex, so a look-alike string does not trip it.
const (
	confPrivateKey = 0.98 // a PEM PRIVATE KEY block is unambiguous structure
	confAWSKey     = 0.92 // a prefixed 20-char key id is highly distinctive
	confJWT        = 0.85 // structural: the header base64url-decodes to a JOSE header
	confAPIToken   = 0.90 // a vendor-prefixed token (ghp_, xoxb-, sk-…) is distinctive
)

// --- Private keys (PEM) ---

type privateKey struct{}

// Matches a full PEM private-key block (RSA/EC/OPENSSH/PKCS#8/generic). The
// `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----` framing is the
// artifact; the body is not decoded (no need — the framing alone is conclusive).
var privateKeyRe = regexp.MustCompile(
	`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)

func (privateKey) Type() corev1.DetectorType {
	return corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY
}
func (privateKey) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return string(b) }
	valid := func(string) bool { return true } // the header IS the validator
	return countValid(privateKeyRe, text, norm, valid), confPrivateKey
}

// --- AWS access key id ---

type awsAccessKey struct{}

// AWS key ids are a fixed prefix (AKIA/ASIA/AIDA/AROA/…) + 16 uppercase base32
// chars = 20 total. The prefix set is AWS's published resource-id scheme.
var awsKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z2-7]{16}\b`)

func (awsAccessKey) Type() corev1.DetectorType {
	return corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY
}
func (awsAccessKey) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return string(b) }
	valid := func(string) bool { return true } // prefix + charset is the validator
	return countValid(awsKeyRe, text, norm, valid), confAWSKey
}

// --- JWT ---

type jwt struct{}

// A compact JWT is three base64url segments. The candidate regex is deliberately
// loose; validJWT is the real filter — it base64url-decodes the FIRST segment and
// requires it to be a JOSE header (a JSON object naming an `alg`). This rejects
// any three-dotted-token look-alike, keeping the false-positive rate low.
var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)

func (jwt) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_JWT }
func (jwt) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return string(b) }
	return countValid(jwtRe, text, norm, validJWT), confJWT
}

// validJWT decodes the header segment and checks it is a JOSE header. It does not
// verify the signature (that needs a key it does not have) — the goal is to
// distinguish a real token structure from a coincidental three-part string, not
// to authenticate it.
func validJWT(token string) bool {
	dot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return false
	}
	hdr, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return false
	}
	// A JOSE header is a JSON object naming an algorithm. A substring check on the
	// decoded header avoids a JSON parser in the classifier while still requiring
	// the decoded bytes to look like a header (rejects arbitrary base64url).
	s := string(hdr)
	return len(s) >= 2 && s[0] == '{' && containsSub(s, `"alg"`)
}

// containsSub is a tiny substring test (avoids importing strings for one use and
// keeps the detector's dependency surface minimal — this code runs in the worker).
func containsSub(hay, needle string) bool {
	if len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// --- Vendor-prefixed API tokens ---

type apiToken struct{}

// Distinctive vendor prefixes: GitHub (ghp_/gho_/ghs_/ghr_/github_pat_), Slack
// (xoxb-/xoxp-/xoxa-/xoxr-), Google API keys (AIza…), OpenAI/Anthropic (sk-…),
// Stripe (sk_live_/pk_live_). The prefix carries the confidence; a length floor
// on the secret body filters truncated look-alikes.
var apiTokenRe = regexp.MustCompile(
	`\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}\b` +
		`|\bgithub_pat_[A-Za-z0-9_]{20,}\b` +
		`|\bxox[baprs]-[A-Za-z0-9-]{10,}\b` +
		`|\bAIza[A-Za-z0-9_-]{20,}\b` +
		`|\b(?:sk|pk)_live_[A-Za-z0-9]{20,}\b` +
		`|\bsk-[A-Za-z0-9-]{20,}\b`)

func (apiToken) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_API_TOKEN }
func (apiToken) Scan(text []byte) (int, float64) {
	norm := func(b []byte) string { return string(b) }
	valid := func(string) bool { return true } // prefix + length floor is the validator
	return countValid(apiTokenRe, text, norm, valid), confAPIToken
}
