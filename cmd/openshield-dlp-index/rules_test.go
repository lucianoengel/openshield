package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
)

// SIGNING A RULE BUNDLE (D297).
//
// The worker verified signed bundles and nothing produced one. These tests assert the loop CLOSES —
// that what this tool writes is what the worker's own loader accepts — because a signing tool whose
// output the verifier rejects is the same gap with an extra step.

func writeRules(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func keypair(t *testing.T, dir string) (privPath string, pub ed25519.PublicKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, "op.key")
	if err := os.WriteFile(privPath, sk, 0o600); err != nil {
		t.Fatal(err)
	}
	return privPath, pk
}

func TestASignedBundleLoadsWithTheWorkersOwnLoader(t *testing.T) {
	dir := t.TempDir()
	in := writeRules(t, dir, `[{"rule_id":1,"pattern":"ACME-[0-9]{6}","confidence":0.9},
	                           {"rule_id":2,"pattern":"[0-9]{16}","confidence":0.8,"validator":"luhn"}]`)
	key, pub := keypair(t, dir)
	out := filepath.Join(dir, "rules.bundle")

	rules([]string{"--in", in, "--key", key, "--out", out})

	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no bundle written: %v", err)
	}
	// THE WORKER'S LOADER, not a local re-implementation — that is the whole assertion.
	loaded, err := classify.LoadSignedRules(signed, pub)
	if err != nil {
		t.Fatalf("the worker's loader rejected our own bundle: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("loaded %d rules, want 2", len(loaded))
	}
	// A DIFFERENT key must not verify it, or the signature is decoration.
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := classify.LoadSignedRules(signed, other); err == nil {
		t.Error("a bundle verified against the WRONG operator key — the signature is what stops a " +
			"compromised distribution path injecting detection rules")
	}
}

// TestABadPatternIsRefusedBeforeTheBundleIsWritten is the authoring-time property.
//
// Without it the operator's feedback arrives in production, where the worker fails closed to built-ins
// and their custom detection is silently absent — the failure is safe, and invisible.
func TestABadPatternIsRefusedBeforeTheBundleIsWritten(t *testing.T) {
	if os.Getenv("OPENSHIELD_RULES_FATAL_CHILD") == "1" {
		dir := os.Getenv("OPENSHIELD_RULES_DIR")
		rules([]string{"--in", filepath.Join(dir, "rules.json"), "--key", filepath.Join(dir, "op.key"),
			"--out", filepath.Join(dir, "rules.bundle")})
		return
	}
	dir := t.TempDir()
	writeRules(t, dir, `[{"rule_id":3,"pattern":"([unclosed","confidence":0.5}]`)
	keypair(t, dir)

	// `rules` exits the process on failure, so the refusal is observed in a subprocess. Asserting that
	// NO FILE WAS WRITTEN is the point: a tool that writes a broken artifact and then complains has
	// already put the broken artifact where someone will deploy it.
	if code := runSelf(t, dir); code == 0 {
		t.Fatal("a bundle with an uncompilable pattern was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "rules.bundle")); !os.IsNotExist(err) {
		t.Error("a bundle file was written despite the rules not compiling")
	}
}

// runSelf re-executes this test binary in the child mode above and returns its exit code.
func runSelf(t *testing.T, dir string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "TestABadPatternIsRefusedBeforeTheBundleIsWritten")
	cmd.Env = append(os.Environ(), "OPENSHIELD_RULES_FATAL_CHILD=1", "OPENSHIELD_RULES_DIR="+dir)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("running the child: %v", err)
	return -1
}
