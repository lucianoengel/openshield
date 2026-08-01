//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEuropeanNationalIDsAreDetectedByTheShippedWorker is DLP-10 end to end.
//
// The detector set could find a Brazilian CPF, a US SSN and an Indian Aadhaar, and nothing a French or
// Spanish deployment would actually be holding — which is most of the GDPR-relevant personal data in
// Europe. This drives the real engine and its sandboxed worker over a file containing both, and a policy
// written against the hits.
//
// It also pins the DIFFERENCE between them, which is the interesting half: a French NIR stands on its
// own check, and a Spanish DNI is reported only near its context because one in twenty-three arbitrary
// "8 digits then a letter" tokens passes its check by chance.
const euIDPolicy = `package openshield
import rego.v1
es if { some h in input.classification; h.type == "DETECTOR_TYPE_ES_DNI" }
fr if { some h in input.classification; h.type == "DETECTOR_TYPE_FR_NIR" }
decision := {"action":"ALERT","reason":"European national identifier"} if { es }
decision := {"action":"ALERT","reason":"European national identifier"} if { fr }
decision := {"action":"ALLOW","reason":"no national identifier"} if { not es; not fr }`

func TestEuropeanNationalIDsAreDetectedByTheShippedWorker(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	policy := filepath.Join(work, "euid.rego")
	if err := os.WriteFile(policy, []byte(euIDPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
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

	// A FILE THAT LOOKS LIKE ONE BUT IS NOT, first. Without this, the assertion below would pass for a
	// worker that alerts on any file at all.
	//
	// The bare DNI is the important case: it is a REAL, checksum-valid identifier with no context word
	// near it, and it must NOT be reported — that is the whole reason the Spanish detector is gated.
	if err := os.WriteFile(filepath.Join(watch, "ordinary.txt"),
		[]byte("order 12345678Z shipped; batch 269054958815781 packed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("%d alerts for a file with a context-free DNI-shaped token and a 15-digit run whose "+
			"key does not check. Both are shapes that occur constantly, and a detector that reports "+
			"them is one an operator switches off", n)
	}

	// Now the real thing: a French NIR standing alone, and a Spanish DNI beside its keyword.
	if err := os.WriteFile(filepath.Join(watch, "expediente.txt"),
		[]byte("Cliente DNI 12345678Z\nSécurité sociale 2 69 05 49 588 157 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 90*time.Second, "the European national identifiers to be detected", func() bool {
		return alerts() > 0
	})
}
