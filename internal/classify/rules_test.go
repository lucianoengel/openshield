package classify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func bundle(rules ...*corev1.DetectorRule) *corev1.RuleBundle {
	return &corev1.RuleBundle{Rules: rules, IssuedAt: 1_700_000_000}
}

// The full loop: an operator authors a rule, signs the bundle, the node verifies + loads
// it, and a custom detector fires on matching content — reported as the generic CUSTOM
// type (no per-rule name leaks).
func TestSignedRulesRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// A custom rule: an internal project code "PRJ-" + 6 digits, no validator.
	signed, err := classify.SignRuleBundle(bundle(&corev1.DetectorRule{
		RuleId: 1, Pattern: `\bPRJ-\d{6}\b`, Confidence: 0.8,
		Validator: corev1.RuleValidator_RULE_VALIDATOR_NONE,
	}), priv)
	if err != nil {
		t.Fatal(err)
	}

	rules, err := classify.LoadSignedRules(signed, pub)
	if err != nil {
		t.Fatalf("loading a validly-signed bundle: %v", err)
	}
	c := classify.New().WithRules(rules)
	hits, err := c.Classify(context.Background(), strings.NewReader("ref PRJ-004217 in the doc"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CUSTOM {
			found = true
			if h.GetConfidence() != 0.8 {
				t.Errorf("custom confidence = %v, want 0.8", h.GetConfidence())
			}
		}
	}
	if !found {
		t.Error("the custom rule did not fire on matching content")
	}

	// The built-ins still work alongside custom rules (custom ADDS, never replaces).
	cpfHits, _ := c.Classify(context.Background(), strings.NewReader("cpf 111.444.777-35"))
	if !hasType(cpfHits, corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a built-in detector stopped firing after adding custom rules")
	}
}

// A LUHN-validated custom rule uses the built-in validator, not operator code.
func TestSignedRulesLuhnValidator(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := classify.SignRuleBundle(bundle(&corev1.DetectorRule{
		RuleId: 2, Pattern: `\b\d{16}\b`, Confidence: 0.7,
		Validator: corev1.RuleValidator_RULE_VALIDATOR_LUHN,
	}), priv)
	rules, err := classify.LoadSignedRules(signed, pub)
	if err != nil {
		t.Fatal(err)
	}
	c := classify.New().WithRules(rules)
	// 4111111111111111 passes Luhn; 4111111111111112 does not.
	if !hasTypeR(t, c, "pay 4111111111111111 now", corev1.DetectorType_DETECTOR_TYPE_CUSTOM) {
		t.Error("Luhn-valid number did not fire the custom rule")
	}
	if hasTypeR(t, c, "pay 4111111111111112 now", corev1.DetectorType_DETECTOR_TYPE_CUSTOM) {
		t.Error("Luhn-INVALID number fired the custom rule — the validator was not applied")
	}
}

func hasTypeR(t *testing.T, c *classify.Classifier, text string, want corev1.DetectorType) bool {
	t.Helper()
	hits, err := c.Classify(context.Background(), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return hasType(hits, want)
}

// Fail-closed: every non-verifying bundle loads NOTHING and errors — the security core of
// D3. A compromised control plane can distribute any of these and none inject rules.
func TestSignedRulesRejectsUntrusted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := bundle(&corev1.DetectorRule{RuleId: 1, Pattern: `\bSECRET\b`, Confidence: 0.9})
	signed, _ := classify.SignRuleBundle(good, priv)

	// Tampered bundle: flip a byte of the signed message so the signature no longer covers it.
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff

	// Unsigned: a SignedRuleBundle with an empty signature.
	raw, _ := proto.Marshal(good)
	unsigned, _ := proto.Marshal(&corev1.SignedRuleBundle{Bundle: raw})

	cases := map[string]struct {
		signed []byte
		key    ed25519.PublicKey
	}{
		"wrong key":       {signed, otherPub},
		"tampered bundle": {tampered, pub},
		"unsigned":        {unsigned, pub},
		"garbage":         {[]byte("not a proto at all"), pub},
	}
	for name, tc := range cases {
		rules, err := classify.LoadSignedRules(tc.signed, tc.key)
		if err == nil {
			t.Errorf("%s: loaded without error — must fail closed", name)
		}
		if rules != nil {
			t.Errorf("%s: returned %d rules — a rejected bundle must load NOTHING", name, len(rules))
		}
	}
}

// A rule with an uncompilable pattern (or an out-of-range confidence) fails the WHOLE
// bundle — a partial load is an ambiguous security state.
func TestSignedRulesRejectsBadRule(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, bad := range []*corev1.DetectorRule{
		{RuleId: 1, Pattern: `(unclosed`, Confidence: 0.5},                              // bad regex
		{RuleId: 2, Pattern: `x`, Confidence: 1.5},                                      // confidence out of range
		{RuleId: 3, Pattern: `x`, Confidence: 0.5, Validator: corev1.RuleValidator(99)}, // unknown validator
		{RuleId: 4, Pattern: strings.Repeat("a", 5000), Confidence: 0.5},                // pattern too long
	} {
		signed, _ := classify.SignRuleBundle(bundle(bad), priv)
		if rules, err := classify.LoadSignedRules(signed, pub); err == nil || rules != nil {
			t.Errorf("bad rule (id %d) was accepted: rules=%v err=%v", bad.GetRuleId(), rules, err)
		}
	}
}
