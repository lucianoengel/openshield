package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openshield-anchor is the runnable half of external anchoring (T-019/D38, D64): without it AnchorHead
// never runs and a deployment stays permanently Completeness: UNVERIFIED. 98 lines, no test file.
//
// It holds ONLY the witness key and opens the ledger SIGNER-LESS, because the whole point of a witness is
// that it is a party the ledger writer cannot impersonate. That property is structural — it is expressed
// by which constructor is called — so what is testable here is the gate in front of it: the key it accepts.

func writeBytes(t *testing.T, dir, name string, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The witness key is a PRIVATE Ed25519 key (64 bytes). The plausible mistakes are handing it the PUBLIC
// half (32 bytes), a base64 file rather than a raw one, or a truncated copy — and ed25519 does not fail
// cleanly on any of them. A short key must be refused here, naming the file, rather than producing a
// witness that signs nothing verifiable and leaves every anchor quietly worthless.
func TestTheWitnessKeyMustBeAFullPrivateKey(t *testing.T) {
	dir := t.TempDir()

	good := writeBytes(t, dir, "good.key", ed25519.PrivateKeySize)
	w, err := loadWitness(good)
	if err != nil || w == nil {
		t.Fatalf("a correctly sized witness key was refused: %v", err)
	}

	for _, n := range []int{
		0,
		1,
		ed25519.PublicKeySize,      // the PUBLIC half by mistake
		ed25519.PrivateKeySize - 1, // truncated by one byte
		ed25519.PrivateKeySize + 1,
		88, // roughly what base64 of a 64-byte key looks like as a file
	} {
		p := writeBytes(t, dir, "bad.key", n)
		if _, err := loadWitness(p); err == nil {
			t.Errorf("a %d-byte witness key was accepted for a %d-byte slot; the anchors it signed would "+
				"verify against nothing and the deployment would still report itself witnessed",
				n, ed25519.PrivateKeySize)
		}
	}

	if _, err := loadWitness(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing witness key file was accepted")
	}
}

// WITHOUT A WITNESS KEY THE TOOL MUST NOT RUN. Anchoring with no key, or silently generating one, would
// produce an anchor the ledger operator could have made themselves — which is exactly the thing an
// external witness exists to rule out (T-019: "an anchor witnessed by a key the deployer holds attests to
// little"). It must refuse, before touching the database.
func TestItRefusesToRunWithoutAWitnessKey(t *testing.T) {
	t.Setenv("OPENSHIELD_WITNESS_KEY", "")
	// A DSN that cannot possibly connect: if the refusal did not happen first, this would hang or fail
	// with a database error instead of the usage code.
	t.Setenv("OPENSHIELD_DSN", "postgres://127.0.0.1:1/nope?sslmode=disable&connect_timeout=1")

	if code := run(nil); code != 2 {
		t.Fatalf("run with no witness key returned %d, want 2 (usage) — it must refuse BEFORE opening the "+
			"ledger, or an operator who forgot the key learns about it as a database error", code)
	}
	if code := run([]string{"--dsn", "postgres://127.0.0.1:1/nope"}); code != 2 {
		t.Fatalf("run with a dsn but no witness key returned %d, want 2", code)
	}
}

// ASSERTING ON THE MESSAGE, NOT JUST THE EXIT CODE, and the difference is the whole test.
//
// The first version checked only that run returned 1. It passed against a mutant with the key check
// removed, because run then went on to open the ledger, failed against an unreachable DSN, and returned 1
// anyway. It was passing for the wrong reason — the same trap as D399's open gate, which passed for lack
// of privilege rather than for correctness.
//
// So stderr is captured and the message must name the KEY. That also pins the ordering the test's name
// claims: the key is rejected BEFORE the database is touched, so an operator with a bad key sees a key
// error rather than a connection error.
func TestAnUnusableWitnessKeyIsReportedBeforeTheLedgerIsOpened(t *testing.T) {
	dir := t.TempDir()
	short := writeBytes(t, dir, "short.key", 8)
	t.Setenv("OPENSHIELD_DSN", "postgres://127.0.0.1:1/nope?sslmode=disable&connect_timeout=1")

	code, stderr := runCapturingStderr(t, []string{"--witness", short})

	// Exit 1, not 2: the invocation was well-formed, the key was not.
	if code != 1 {
		t.Fatalf("run with a malformed witness key returned %d, want 1\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "witness key") || !strings.Contains(stderr, "8 bytes") {
		t.Fatalf("the failure does not name the key that caused it, so it is indistinguishable from the "+
			"ledger being unreachable:\n%s", stderr)
	}
	if strings.Contains(stderr, "opening ledger") {
		t.Fatalf("the ledger was opened despite an unusable witness key:\n%s", stderr)
	}
}

// runCapturingStderr swaps os.Stderr for a pipe around one run() call.
func runCapturingStderr(t *testing.T, args []string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	code := run(args)

	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return code, out
}

func TestBadFlagsAreAUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"--nonsense"},
		{"--interval", "not-a-duration", "--witness", "x"},
	} {
		if code := run(args); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}

func TestEnvFallsBackToItsDefault(t *testing.T) {
	const key = "OPENSHIELD_ANCHOR_TEST"
	t.Setenv(key, "")
	if got := env(key, "fallback"); got != "fallback" {
		t.Fatalf("env unset = %q", got)
	}
	t.Setenv(key, "set")
	if got := env(key, "fallback"); got != "set" {
		t.Fatalf("env set = %q", got)
	}
}
