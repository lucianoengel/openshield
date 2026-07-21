package encryptlocal_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

func key32(b byte) []byte {
	k := make([]byte, encryptlocal.KeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

// 3.1 — encryption genuinely makes the file unreadable: on-disk bytes differ
// from the plaintext, the right key recovers the EXACT original, and a wrong key
// fails (GCM auth). This is the guard against "encryption" that is really a
// rename or a reversible transform.
func TestEncryptsUnreadablyAndRecovers(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "leak.csv")
	plaintext := []byte("cpf,name\n123.456.789-09,alice\n")
	if err := os.WriteFile(f, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	enf, err := encryptlocal.WithKey(key32(0x01))
	if err != nil {
		t.Fatal(err)
	}

	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{Action: corev1.Action_ACTION_ENCRYPT_LOCAL}, f); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	onDisk, _ := os.ReadFile(f)
	if bytes.Equal(onDisk, plaintext) {
		t.Fatal("on-disk bytes equal the plaintext — the file was not encrypted")
	}
	if bytes.Contains(onDisk, []byte("alice")) {
		t.Fatal("plaintext content survives in the encrypted file")
	}

	// Right key recovers the EXACT original.
	got, err := encryptlocal.Decrypt(key32(0x01), onDisk)
	if err != nil {
		t.Fatalf("decrypt with correct key failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered bytes != original:\n got %q\nwant %q", got, plaintext)
	}

	// Wrong key fails — the file is genuinely unreadable without the key.
	if _, err := encryptlocal.Decrypt(key32(0x02), onDisk); err == nil {
		t.Fatal("decrypt with a WRONG key succeeded — GCM authentication not enforced")
	}
}

// 3.2 — idempotent: re-encrypting an already-encrypted file does not
// double-encrypt or corrupt it; it still recovers to the original plaintext.
func TestIdempotentReEncrypt(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "doc.txt")
	plaintext := []byte("secret material")
	_ = os.WriteFile(f, plaintext, 0o600)
	enf, _ := encryptlocal.WithKey(key32(0x07))
	dec := &corev1.Decision{Action: corev1.Action_ACTION_ENCRYPT_LOCAL}

	if err := enf.EnforceTarget(context.Background(), dec, f); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(f)
	// Second enforcement must be a no-op on already-encrypted content.
	if err := enf.EnforceTarget(context.Background(), dec, f); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(f)
	if !bytes.Equal(first, second) {
		t.Fatal("a second enforcement changed the file — not idempotent (double-encrypted)")
	}
	// And it still recovers to the ORIGINAL plaintext in ONE decrypt (not two).
	got, err := encryptlocal.Decrypt(key32(0x07), second)
	if err != nil {
		t.Fatalf("decrypt after re-enforce failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("re-encrypted file recovered to %q, want the original %q", got, plaintext)
	}
}

// 3.3 — an empty target is an error (never a silent no-op), and the enforcer
// advertises ONLY encrypt-local.
func TestEmptyTargetAndCapabilities(t *testing.T) {
	enf, _ := encryptlocal.WithKey(key32(0x03))
	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{}, ""); err == nil {
		t.Error("empty target did not error — a no-op enforcement looks like success")
	}
	if err := enf.Enforce(context.Background(), &corev1.Decision{}); err == nil {
		t.Error("Enforce with no target did not error")
	}
	// CanEnforce matches ENCRYPT_LOCAL and nothing else.
	if !core.CanEnforce(enf, &corev1.Decision{Action: corev1.Action_ACTION_ENCRYPT_LOCAL}) {
		t.Error("enforcer does not advertise ENCRYPT_LOCAL")
	}
	if core.CanEnforce(enf, &corev1.Decision{Action: corev1.Action_ACTION_QUARANTINE_LOCAL}) {
		t.Error("enforcer wrongly advertises QUARANTINE_LOCAL")
	}
}

// A wrong-length key is a load error — never a weak or truncated cipher.
func TestKeyLengthEnforced(t *testing.T) {
	if _, err := encryptlocal.WithKey([]byte("short")); err == nil {
		t.Error("a short key was accepted")
	}
}
