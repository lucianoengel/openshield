package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func fires(t *testing.T, c *classify.Classifier, text string, want corev1.DetectorType) bool {
	t.Helper()
	hits, err := c.Classify(context.Background(), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.GetDetectorType() == want {
			return true
		}
	}
	return false
}

// writeBundle signs a one-rule bundle and writes the bundle + public key to disk, returning
// their paths.
func writeBundle(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey) (bundlePath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	signed, err := classify.SignRuleBundle(&corev1.RuleBundle{Rules: []*corev1.DetectorRule{{
		RuleId: 1, Pattern: `\bPRJ-\d{6}\b`, Confidence: 0.8,
		Validator: corev1.RuleValidator_RULE_VALIDATOR_NONE,
	}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath = filepath.Join(dir, "rules.bundle")
	pubPath = filepath.Join(dir, "rules.pub")
	if err := os.WriteFile(bundlePath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath, pubPath
}

// HON-1: a signed rule bundle on disk causes a custom detector to fire through the real
// worker classifier — the D100 feature is now reachable in production.
func TestLoadClassifierAppliesSignedRules(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundlePath, pubPath := writeBundle(t, priv, pub)
	t.Setenv("OPENSHIELD_RULES_BUNDLE", bundlePath)
	t.Setenv("OPENSHIELD_RULES_PUBKEY", pubPath)

	c := loadClassifier()
	if !fires(t, c, "ref PRJ-004217 in the doc", corev1.DetectorType_DETECTOR_TYPE_CUSTOM) {
		t.Error("the signed custom rule did not fire — HON-1 wiring missing")
	}
	// A built-in still works alongside.
	if !fires(t, c, "cpf 111.444.777-35", corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a built-in detector stopped firing after loading custom rules")
	}
}

// A TAMPERED bundle loads nothing (fail-closed on the rules) but the worker still classifies
// with the built-ins — availability preserved, no unverified rule trusted.
func TestLoadClassifierRejectsTamperedBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundlePath, pubPath := writeBundle(t, priv, pub)
	// Corrupt the signed bundle on disk.
	b, _ := os.ReadFile(bundlePath)
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(bundlePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_RULES_BUNDLE", bundlePath)
	t.Setenv("OPENSHIELD_RULES_PUBKEY", pubPath)

	c := loadClassifier()
	if fires(t, c, "ref PRJ-004217 in the doc", corev1.DetectorType_DETECTOR_TYPE_CUSTOM) {
		t.Error("a tampered bundle's custom rule fired — verification bypassed")
	}
	// Built-ins still classify (the worker did not refuse to run).
	if !fires(t, c, "cpf 111.444.777-35", corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("built-ins stopped working after a rejected bundle — availability lost")
	}
}

// A wrong-key bundle is also rejected (fail-closed).
func TestLoadClassifierRejectsWrongKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundlePath, _ := writeBundle(t, priv, pub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	wrongPubPath := filepath.Join(dir, "wrong.pub")
	if err := os.WriteFile(wrongPubPath, otherPub, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_RULES_BUNDLE", bundlePath)
	t.Setenv("OPENSHIELD_RULES_PUBKEY", wrongPubPath)

	if fires(t, loadClassifier(), "ref PRJ-004217", corev1.DetectorType_DETECTOR_TYPE_CUSTOM) {
		t.Error("a bundle verified against the WRONG key fired a custom rule")
	}
}
