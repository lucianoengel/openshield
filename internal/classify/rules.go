package classify

import (
	"crypto/ed25519"
	"fmt"
	"regexp"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Admin-authorable, SIGNED custom detectors (Phase D3).
//
// An operator authors declarative rules (a regex + a named validator, never code), signs
// the bundle with an operator key, and the node loads it ONLY after verifying the
// signature against a trusted operator public key. This is the T2 model (D14): the control
// plane may DISTRIBUTE a bundle, but a compromised control plane cannot FORGE the operator
// signature, so it cannot inject detection rules — the node accepts only operator-approved,
// operator-signed data. An unsigned, tampered, or wrong-key bundle is REJECTED, never
// loaded (fail-closed).
//
// Rules ship a PATTERN, not executable code, so authoring cannot introduce a
// code-execution path; the pattern runs on Go's RE2 engine (linear time, no catastrophic
// backtracking / ReDoS). Bundles are bounded (rule count, pattern length) so a bundle
// cannot itself be a resource-exhaustion vector.

const (
	// maxRules bounds a bundle; maxPatternLen bounds a single rule's regex source.
	maxRules      = 256
	maxPatternLen = 4096
)

// LoadSignedRules verifies a SignedRuleBundle against a trusted operator public key and
// compiles its rules into runtime detectors. It returns an error — and NO detectors — if
// the signature is missing/invalid, the key is wrong, the bundle is malformed, a rule's
// pattern does not compile, or a limit is exceeded. Fail-closed: a bundle that does not
// fully verify and compile loads nothing.
func LoadSignedRules(signed []byte, trustedPub ed25519.PublicKey) ([]Detector, error) {
	if len(trustedPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("rules: trusted key must be %d bytes", ed25519.PublicKeySize)
	}
	var sb corev1.SignedRuleBundle
	if err := proto.Unmarshal(signed, &sb); err != nil {
		return nil, fmt.Errorf("rules: malformed signed bundle: %w", err)
	}
	if len(sb.GetSignature()) == 0 {
		return nil, fmt.Errorf("rules: bundle is unsigned")
	}
	// Verify BEFORE parsing the inner bundle — an unverified bundle's contents are never
	// interpreted, so a forged bundle cannot even reach the regex compiler.
	if !ed25519.Verify(trustedPub, sb.GetBundle(), sb.GetSignature()) {
		return nil, fmt.Errorf("rules: signature does not verify against the trusted operator key")
	}

	var bundle corev1.RuleBundle
	if err := proto.Unmarshal(sb.GetBundle(), &bundle); err != nil {
		return nil, fmt.Errorf("rules: malformed rule bundle: %w", err)
	}
	if len(bundle.GetRules()) > maxRules {
		return nil, fmt.Errorf("rules: bundle has %d rules, over the %d limit", len(bundle.GetRules()), maxRules)
	}

	var out []Detector
	for _, r := range bundle.GetRules() {
		d, err := compileRule(r)
		if err != nil {
			// One bad rule fails the WHOLE bundle — a partially-loaded bundle is an
			// ambiguous security state (which rules are active?). All or nothing.
			return nil, fmt.Errorf("rules: rule %d: %w", r.GetRuleId(), err)
		}
		out = append(out, d)
	}
	return out, nil
}

// SignRuleBundle marshals a RuleBundle and signs it with an operator private key, producing
// the bytes LoadSignedRules verifies. This is the operator-authoring side.
func SignRuleBundle(bundle *corev1.RuleBundle, priv ed25519.PrivateKey) ([]byte, error) {
	raw, err := proto.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("rules: marshaling bundle: %w", err)
	}
	sig := ed25519.Sign(priv, raw)
	return proto.Marshal(&corev1.SignedRuleBundle{Bundle: raw, Signature: sig})
}

func compileRule(r *corev1.DetectorRule) (Detector, error) {
	if r.GetPattern() == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if len(r.GetPattern()) > maxPatternLen {
		return nil, fmt.Errorf("pattern over %d bytes", maxPatternLen)
	}
	if r.GetConfidence() <= 0 || r.GetConfidence() >= 1 {
		return nil, fmt.Errorf("confidence %v out of (0,1)", r.GetConfidence())
	}
	re, err := regexp.Compile(r.GetPattern())
	if err != nil {
		return nil, fmt.Errorf("bad pattern: %w", err)
	}
	norm, valid, err := validatorFor(r.GetValidator())
	if err != nil {
		return nil, err
	}
	return customDetector{re: re, conf: r.GetConfidence(), norm: norm, valid: valid}, nil
}

// validatorFor maps a named validator to its normalize + validate functions, reusing the
// built-in validators (never operator-supplied code).
func validatorFor(v corev1.RuleValidator) (func([]byte) string, func(string) bool, error) {
	switch v {
	case corev1.RuleValidator_RULE_VALIDATOR_NONE:
		return func(b []byte) string { return string(b) }, func(string) bool { return true }, nil
	case corev1.RuleValidator_RULE_VALIDATOR_LUHN:
		return stripNonDigits, validLuhn, nil
	default:
		return nil, nil, fmt.Errorf("unknown validator %v", v)
	}
}

// customDetector is a compiled operator rule. It reports the generic DETECTOR_TYPE_CUSTOM
// (never a per-rule name) so a custom rule cannot leak what it detects through the
// classification (D10/D29 — the closed enum is preserved).
type customDetector struct {
	re    *regexp.Regexp
	conf  float64
	norm  func([]byte) string
	valid func(string) bool
}

func (customDetector) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_CUSTOM }
func (d customDetector) Scan(text []byte) (int, float64) {
	return countValid(d.re, text, d.norm, d.valid), d.conf
}

// WithRules returns a classifier that runs the built-in detectors PLUS the given custom
// rules (typically the output of LoadSignedRules). The built-ins are always present; custom
// rules ADD coverage, never replace or disable a built-in.
func (c *Classifier) WithRules(rules []Detector) *Classifier {
	merged := make([]Detector, 0, len(c.detectors)+len(rules))
	merged = append(merged, c.detectors...)
	merged = append(merged, rules...)
	return &Classifier{detectors: merged}
}
