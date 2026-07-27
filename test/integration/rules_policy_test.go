//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SIGNED CUSTOM RULES AND POLICY PACKS, IN A RUNNING ENGINE (D306).
//
// D297 built the tool that SIGNS a detector bundle, and verified by hand that the worker loads it. That
// is the shape this session keeps finding dangerous — a producer and a consumer agreeing in a shell
// session and nothing holding them together — so it belongs in the gate.
//
// The bundle path is FAIL-CLOSED (HON-1/D100): an unverified bundle loads NOTHING and the worker keeps
// its built-in detectors. Availability is preserved and detection silently narrows, which is the safe
// direction and also the invisible one: an operator whose bundle stopped verifying sees a working
// product that no longer looks for what they wrote.

const customRuleAlert = `package openshield
import rego.v1
custom if { some h in input.classification; h.type == "DETECTOR_TYPE_CUSTOM" }
decision := {"action":"ALERT","reason":"custom rule"} if { custom }
decision := {"action":"ALLOW","reason":"clean"} if { not custom }`

func TestASignedRuleBundleIsLoadedByARunningEngine(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work, watch := t.TempDir(), t.TempDir()

	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	// A pattern nothing built in would match, so a hit can only come from the operator's own rule.
	rules := filepath.Join(work, "rules.json")
	if err := os.WriteFile(rules,
		[]byte(`[{"rule_id":1,"pattern":"ACME-CONFIDENTIAL-[0-9]{4}","confidence":0.95}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(work, "rules.bundle")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "rules",
		"--in", rules, "--key", filepath.Join(work, "op.key"), "--out", bundle); err != nil {
		t.Fatalf("signing the bundle: %v\n%s", err, out)
	}

	policy := filepath.Join(work, "custom.rego")
	if err := os.WriteFile(policy, []byte(customRuleAlert), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_RULES_BUNDLE=" + bundle,
		"OPENSHIELD_RULES_PUBKEY=" + filepath.Join(work, "op.pub"),
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Content that matches NOTHING must not alert — otherwise the assertion below would pass against a
	// classifier that fires on everything.
	if err := os.WriteFile(filepath.Join(watch, "clean.txt"), []byte("ordinary notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("clean content produced %d alert(s)\n%s", n, eng.Output())
	}

	if err := os.WriteFile(filepath.Join(watch, "secret.txt"),
		[]byte("ref ACME-CONFIDENTIAL-4471\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "the operator's own rule to fire in the running worker", func() bool {
		return alerts() > 0
	})
}

// TestAnUnverifiedRuleBundleNarrowsDetectionSilentlyAndSaysSo is the fail-closed half.
//
// The worker keeps running with its built-ins, which is right — refusing to start would trade all of
// today's detection for one misconfigured file. But it means the failure is INVISIBLE in behaviour, so
// the only signal an operator gets is the message. That makes the message the control.
func TestAnUnverifiedRuleBundleNarrowsDetectionSilentlyAndSaysSo(t *testing.T) {
	work := t.TempDir()
	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "other.key"), "--out-pub", filepath.Join(work, "other.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	rules := filepath.Join(work, "rules.json")
	if err := os.WriteFile(rules,
		[]byte(`[{"rule_id":1,"pattern":"ACME-[0-9]{4}","confidence":0.9}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(work, "rules.bundle")
	// Signed by the WRONG operator: well-formed, correctly signed, untrusted.
	if out, err := runCapture(t, "openshield-dlp-index", nil, "rules",
		"--in", rules, "--key", filepath.Join(work, "other.key"), "--out", bundle); err != nil {
		t.Fatalf("signing: %v\n%s", err, out)
	}

	out, err := runCapture(t, "openshield-worker", []string{
		"OPENSHIELD_RULES_BUNDLE=" + bundle,
		"OPENSHIELD_RULES_PUBKEY=" + filepath.Join(work, "op.pub"),
	})
	// The worker RUNS (it is started here without stdin, so it exits on its own) — the point is that it
	// did not accept the bundle and said which way it failed.
	_ = err
	if !contains(out, "rejected") || !contains(out, "built-ins only") {
		t.Errorf("an untrusted bundle produced no clear notice. The worker keeps its built-in detectors, "+
			"so nothing about its BEHAVIOUR tells an operator their custom rules are gone — the message is "+
			"the only signal there is:\n%s", out)
	}
	if contains(out, "loaded 1 signed custom rule") {
		t.Errorf("an untrusted bundle was LOADED:\n%s", out)
	}
}

// TestAPolicyPackComposesWithTheDefault covers DLP-5b.
func TestAPolicyPackComposesWithTheDefault(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work, watch := t.TempDir(), t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_PACK=pci",
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	if !contains(eng.Output(), "pci") {
		t.Errorf("the engine does not report loading the pci pack — a pack that is configured and not "+
			"loaded is a compliance control an operator believes is on:\n%s", eng.Output())
	}

	// The pack COMPOSES: the default's own detection still fires underneath it. A pack that replaced the
	// default would silently narrow detection to whatever the pack happens to cover.
	if err := os.WriteFile(filepath.Join(watch, "cpf.csv"),
		[]byte("cpf\n111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := openPool(t, stack.DSN)
	Eventually(t, 120*time.Second, "the DEFAULT policy's detection to fire under a loaded pack", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n)
		return n > 0
	})
}
