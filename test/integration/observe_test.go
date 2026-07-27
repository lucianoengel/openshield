//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE OBSERVE PATH, AS BINARIES (ported from deploy/observe-e2e.sh in D296).
//
// This is the scenario the README cites as proof that the product RUNS rather than merely having
// components that pass tests: the shipped engine watches a directory, a file containing a real CPF
// appears, the sandboxed worker classifies it, the policy decides, and an ALERT lands in the
// forward-secure ledger. Then the anchor binary witnesses the head and completeness verifies as
// ANCHORED — the D64 loop that was implemented with zero callers for a whole phase.
//
// It was a shell script outside every gate, which is why it is here. The scripts were not deleted for
// being redundant — this coverage exists nowhere else — but for being unrunnable in the gate that
// decides whether the tree is green.

// TestTheEngineBinaryDetectsAndAuditsARealFile is the walking skeleton, end to end.
func TestTheEngineBinaryDetectsAndAuditsARealFile(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	watch := t.TempDir()
	work := t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	// A REAL CPF, check digits and all. The classifier validates them, so a made-up number would be
	// rejected and the test would prove the pipeline runs while proving nothing about detection.
	if err := os.WriteFile(filepath.Join(watch, "customers.csv"),
		[]byte("name,cpf\nalice,111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pool := openPool(t, stack.DSN)
	// action = 2 is ALERT. Asserted on the LEDGER rather than the engine's log, because the ledger is
	// the evidentiary record and the log is a convenience — a pipeline that logs a detection it did not
	// record has not detected anything that survives.
	Eventually(t, 120*time.Second, "an ALERT in the forward-secure ledger", func() bool {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n); err != nil {
			return false
		}
		return n >= 1
	})

	// And the entry carries NO CONTENT. The classification is type + confidence + count (D10); a ledger
	// row containing the CPF that triggered it would make the evidence store the leak.
	var body string
	if err := pool.QueryRow(Ctx(t),
		`SELECT coalesce(payload::text,'') FROM audit_entries WHERE action = 2 LIMIT 1`).Scan(&body); err == nil {
		if contains(body, "111.444.777-35") || contains(body, "11144477735") {
			t.Errorf("the audit entry CONTAINS the CPF that triggered it — the ledger is the most copied "+
				"and longest-retained artefact in the system, and putting the sensitive value in it makes "+
				"the evidence trail the disclosure:\n%s", body)
		}
	}
}

// TestTheAnchorBinaryMovesCompletenessToAnchored covers D64's operational loop.
//
// `AnchorHead` was implemented, tested, and had zero callers for an entire phase, so every deployment
// verified as permanently UNVERIFIED. This asserts the three binaries close the loop between them.
func TestTheAnchorBinaryMovesCompletenessToAnchored(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	// Something has to be in the ledger for a head to witness.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	if err := os.WriteFile(filepath.Join(watch, "c.csv"), []byte("cpf\n111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := openPool(t, stack.DSN)
	Eventually(t, 120*time.Second, "a ledger entry to witness", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n >= 1
	})

	wdir := filepath.Join(work, "w")
	if out, err := runCapture(t, "openshield-provision", nil, "witness-keygen", "--out", wdir); err != nil {
		t.Fatalf("witness-keygen: %v\n%s", err, out)
	}
	pub, priv := filepath.Join(wdir, "witness-pub"), filepath.Join(wdir, "witness-priv")

	// BEFORE: unverified. Asserted, because a test that only checks the end state would pass against a
	// build that reported "anchored" unconditionally.
	before, err := runCapture(t, "openshieldctl", nil, "verify", "--dsn", stack.DSN, "--witness", pub)
	if err != nil {
		t.Fatalf("verify before: %v\n%s", err, before)
	}
	if !contains(before, "completeness=unverified") {
		t.Fatalf("completeness is not UNVERIFIED before anchoring:\n%s", before)
	}

	out, err := runCapture(t, "openshield-anchor", nil, "--dsn", stack.DSN, "--witness", priv)
	if err != nil || !contains(out, "witnessed head") {
		t.Fatalf("the anchor binary did not witness the head: %v\n%s", err, out)
	}

	after, err := runCapture(t, "openshieldctl", nil, "verify", "--dsn", stack.DSN, "--witness", pub)
	if err != nil {
		t.Fatalf("verify after: %v\n%s", err, after)
	}
	if !contains(after, "completeness=anchored") {
		t.Errorf("completeness did not become ANCHORED after the anchor binary ran — the control that "+
			"catches a truncated ledger only counts if something actually runs it:\nbefore: %s\nafter: %s",
			before, after)
	}
}
