//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// EXACT-DATA MATCHING, end to end (D300).
//
// EDM is the DLP capability that distinguishes "a string that looks like an ID" from "THIS customer's
// ID" — the operator seeds an index from their own sensitive values and the classifier fires only on
// those. It is also the capability I nearly re-implemented in D295: three unused constructors and three
// declared settings made it look unreachable, and the worker in fact loads all three index kinds through
// a different call. Checking beat guessing — and this scenario is what turns that check into something
// that stays true.
//
// It drives the WHOLE operator loop with the shipped binaries: `openshield-dlp-index` builds and SIGNS an
// index from a values file, the engine's worker verifies and loads it, and a file containing a seeded
// value is detected while a file of similar-looking-but-unseeded values is not.

const edmPolicy = `package openshield
import rego.v1
edm_hit if { some h in input.classification; h.type == "DETECTOR_TYPE_EDM" }
decision := {"action":"ALERT","reason":"exact data match"} if { edm_hit }
decision := {"action":"ALLOW","reason":"no exact match"} if { not edm_hit }`

func TestASignedEDMIndexIsBuiltSignedAndUsedByTheEngine(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	// 1. The operator mints a key and builds a SIGNED index from their own sensitive values.
	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	values := filepath.Join(work, "values.txt")
	// Values that are NOT detectable by any built-in detector, so a hit can only come from the index.
	// Seeding a CPF would make the test pass on the built-in CPF detector and prove nothing about EDM.
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\nMM-7731-VV\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building the index: %v\n%s", err, out)
	}

	policy := filepath.Join(work, "edm.rego")
	if err := os.WriteFile(policy, []byte(edmPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. The engine's worker VERIFIES and loads it. Without the public key the worker would take the
	// legacy unsigned path — configuring both is what proves the signed path runs.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + filepath.Join(work, "op.pub"),
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

	// 3. A file with a NON-seeded value of the same shape must NOT alert. This is the half that makes
	// the test about EXACT matching rather than about the pipeline running: a classifier that fired on
	// everything would pass a seeded-value-only test.
	if err := os.WriteFile(filepath.Join(watch, "unseeded.txt"), []byte("ref: AB-1234-CD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("a value that is NOT in the index produced %d alert(s) — EDM's whole claim is that it "+
			"fires on the operator's OWN data, not on anything of a similar shape\n%s", n, eng.Output())
	}

	// 4. A file containing a SEEDED value alerts.
	if err := os.WriteFile(filepath.Join(watch, "seeded.txt"), []byte("customer ref ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "the seeded value to be detected by the signed EDM index", func() bool {
		return alerts() > 0
	})

	// 5. The RAW VALUE is not in the index file. The index ships to endpoints; if it carried the
	// sensitive values it was built from, distributing detection would be distributing the data.
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(blob), "ZX-8842-QQ") {
		t.Error("the built index CONTAINS a raw seeded value — the index is k-anonymised hashes precisely " +
			"so it can be shipped into the sandbox and across a fleet without shipping the data")
	}
}

// TestATamperedEDMIndexIsRefused is the signature half (ADR-9).
//
// A poisoned or swapped index can silently DISABLE exfil detection — the quiet failure, since a detector
// that finds nothing looks exactly like an endpoint with nothing to find.
func TestATamperedEDMIndexIsRefused(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	values := filepath.Join(work, "values.txt")
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle — the shape of a poisoned index in transit.
	blob[len(blob)/2] ^= 0xFF
	if err := os.WriteFile(index, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	// The worker ABORTS on a bad index rather than starting without it: silently classifying with no
	// index would leave an operator believing EDM is on.
	out, err := runCapture(t, "openshield-worker", []string{
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + filepath.Join(work, "op.pub"),
	})
	if err == nil {
		t.Fatalf("the worker STARTED with a tampered index:\n%s", out)
	}
	// The refusal must name the VERIFICATION, not merely fail. A tampered blob also fails to PARSE, so
	// "the worker exited" cannot tell a signature check from a decoder giving up — and a build with the
	// signature check removed still exits, which is exactly what an earlier version of this assertion
	// accepted.
	if !contains(out, "refusing to load an unverified index") {
		t.Errorf("the refusal does not name the signature check, so it is indistinguishable from a parse "+
			"failure:\n%s", out)
	}
}

// TestAnEDMIndexSignedByTheWrongKeyIsRefused isolates the SIGNATURE from parseability.
//
// A tampered index is both unverifiable and unparseable, so refusing it proves little on its own. This
// one is perfectly well-formed and correctly signed — by the wrong operator. Only the signature check
// can reject it, which is the property ADR-9 is for: a swapped index from a compromised distribution
// path silently disabling exfil detection.
func TestAnEDMIndexSignedByTheWrongKeyIsRefused(t *testing.T) {
	work := t.TempDir()
	mint := func(prefix string) (key, pub string) {
		t.Helper()
		key, pub = filepath.Join(work, prefix+".key"), filepath.Join(work, prefix+".pub")
		if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen", "--out-key", key, "--out-pub", pub); err != nil {
			t.Fatalf("keygen: %v\n%s", err, out)
		}
		return key, pub
	}
	attackerKey, _ := mint("attacker")
	_, operatorPub := mint("operator")

	values := filepath.Join(work, "values.txt")
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", attackerKey, "--out", index); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}

	out, err := runCapture(t, "openshield-worker", []string{
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + operatorPub,
	})
	if err == nil {
		t.Fatalf("the worker loaded an index signed by an UNTRUSTED key:\n%s", out)
	}
	if !contains(out, "refusing to load an unverified index") {
		t.Errorf("the refusal does not name the signature check:\n%s", out)
	}
}
