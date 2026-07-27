package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

// RECOVERY IS THE HALF THAT WAS MISSING (D293).
//
// The encrypting enforcer ships and is wired; nothing could decrypt what it produced. These tests assert
// the round trip through the OPERATOR'S COMMAND, not through the library — the library's Encrypt/Decrypt
// pair already had tests, and passing them is exactly what the shipped product did while a user's file
// was unrecoverable.

func writeTemp(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecoverRoundTripsASymmetricBlob(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, encryptlocal.KeySize)
	plain := []byte("the CPF that got this file encrypted")
	blob, err := encryptlocal.Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	in := writeTemp(t, dir, "flagged.enc", blob)
	kp := writeTemp(t, dir, "local.key", key)
	out := filepath.Join(dir, "recovered")

	if code := recoverFile(map[string][]string{"in": {in}, "out": {out}, "key": {kp}}); code != 0 {
		t.Fatalf("recover exited %d", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("recovered %q, want %q", got, plain)
	}
	// THE CIPHERTEXT SURVIVES. It may be the only copy, and a recovery that consumed it would make a
	// failed second attempt unrecoverable.
	if b, err := os.ReadFile(in); err != nil || !bytes.Equal(b, blob) {
		t.Error("recovery modified or removed the encrypted blob")
	}
}

func TestRecoverRoundTripsAnEscrowBlob(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := encryptlocal.GenerateEscrowKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("recovered by the off-endpoint key holder")
	blob, err := encryptlocal.EncryptEscrow(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	in := writeTemp(t, dir, "flagged.enc", blob)
	out := filepath.Join(dir, "recovered")
	code := recoverFile(map[string][]string{
		"in": {in}, "out": {out},
		"escrow-pub":  {writeTemp(t, dir, "escrow.pub", pub)},
		"escrow-priv": {writeTemp(t, dir, "escrow.priv", priv)},
	})
	if code != 0 {
		t.Fatalf("recover exited %d", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("recovered %q, want %q", got, plain)
	}
}

// TestRecoverRefusesToOverwrite is the property that keeps a bad day from getting worse.
func TestRecoverRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{9}, encryptlocal.KeySize)
	blob, err := encryptlocal.Encrypt(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	in := writeTemp(t, dir, "a.enc", blob)
	kp := writeTemp(t, dir, "k", key)
	existing := writeTemp(t, dir, "out", []byte("SOMETHING ELSE"))

	if code := recoverFile(map[string][]string{"in": {in}, "out": {existing}, "key": {kp}}); code == 0 {
		t.Fatal("recovery OVERWROTE an existing file — the destination may hold the only copy of " +
			"something else, and a recovery that destroys data is not a recovery")
	}
	b, err := os.ReadFile(existing)
	if err != nil || string(b) != "SOMETHING ELSE" {
		t.Errorf("the existing file was modified: %q %v", b, err)
	}
}

// TestRecoverNamesTheRightKeyForTheBlob covers the difference between "wrong key" and "wrong KIND of
// key", which an operator cannot tell apart from a decryption failure.
func TestRecoverNamesTheRightKeyForTheBlob(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := encryptlocal.GenerateEscrowKeypair()
	if err != nil {
		t.Fatal(err)
	}
	escrowBlob, err := encryptlocal.EncryptEscrow(pub, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	in := writeTemp(t, dir, "e.enc", escrowBlob)
	symKey := writeTemp(t, dir, "k", bytes.Repeat([]byte{1}, encryptlocal.KeySize))

	// An escrow blob handed the endpoint's symmetric key.
	_, err = recoverBlob(map[string][]string{"key": {symKey}}, escrowBlob)
	if err == nil {
		t.Fatal("an escrow blob was recovered with a symmetric key")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("ESCROW")) {
		t.Errorf("the refusal does not say which key is needed: %v", err)
	}

	// A file that is not OpenShield-encrypted at all.
	_, err = recoverBlob(map[string][]string{"key": {symKey}}, []byte("just a text file"))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("not OpenShield-encrypted")) {
		t.Errorf("a plain file was not identified as such: %v", err)
	}
	_ = in
}

// TestRecoverRejectsATruncatedKey — a short key otherwise fails as a decryption error, which reads as
// "wrong key" and sends an operator looking for a different one that does not exist.
func TestRecoverRejectsATruncatedKey(t *testing.T) {
	dir := t.TempDir()
	short := writeTemp(t, dir, "short.key", []byte("too short"))
	_, err := recoverBlob(map[string][]string{"key": {short}}, append([]byte("OSENC1\x00"), 1, 2, 3))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("bytes, want")) {
		t.Errorf("a truncated key was not reported as truncated: %v", err)
	}
}
