package encryptlocal_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

// 3.1 — escrow seals so the ENDPOINT cannot decrypt: the on-disk blob does not
// open with the public key / endpoint material, DOES open with the private key to
// the exact original, and a wrong private key fails. This is the D57 custody gap
// closed.
func TestEscrowEndpointCannotDecrypt(t *testing.T) {
	pub, priv, err := encryptlocal.GenerateEscrowKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enf, err := encryptlocal.WithEscrowKey(pub) // the endpoint holds ONLY pub
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "leak.csv")
	plaintext := []byte("cpf,name\n111.444.777-35,carol\n")
	if err := os.WriteFile(f, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{Action: corev1.Action_ACTION_ENCRYPT_LOCAL}, f); err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(f)
	if bytes.Equal(onDisk, plaintext) || bytes.Contains(onDisk, []byte("carol")) {
		t.Fatal("plaintext survived the escrow seal")
	}

	// The endpoint's material cannot open it. Two distinct checks:
	// (a) a symmetric decrypt with the public-key bytes as a key is rejected — mode
	//     separation (this fails at magic-routing, before any crypto);
	if _, err := encryptlocal.Decrypt(pub, onDisk); err == nil {
		t.Fatal("an escrow blob opened via symmetric Decrypt — modes crossed")
	}
	// (b) a GENUINE escrow open using only the endpoint's material (the public key
	//     substituted for the private key) reaches box.OpenAnonymous and is
	//     rejected by the CRYPTO, not by routing — proving the seal is a real
	//     barrier, so this assertion would catch a weakened sealed-box, unlike (a).
	if _, err := encryptlocal.DecryptEscrow(pub, pub, onDisk); err == nil {
		t.Fatal("escrow blob opened with only public material — the seal is not a cryptographic barrier")
	}

	// The PRIVATE key recovers the exact original.
	got, err := encryptlocal.DecryptEscrow(pub, priv, onDisk)
	if err != nil {
		t.Fatalf("recovery with the private key failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered %q, want %q", got, plaintext)
	}

	// A WRONG private key fails.
	_, otherPriv, _ := encryptlocal.GenerateEscrowKeypair()
	if _, err := encryptlocal.DecryptEscrow(pub, otherPriv, onDisk); err == nil {
		t.Fatal("a wrong private key opened the escrow blob")
	}
}

// 3.2 — the two modes never silently cross, and escrow is idempotent.
func TestEscrowAndSymmetricDoNotCross(t *testing.T) {
	pub, priv, _ := encryptlocal.GenerateEscrowKeypair()
	symKey := bytes.Repeat([]byte{0x11}, encryptlocal.KeySize)

	escrowBlob, _ := encryptlocal.EncryptEscrow(pub, []byte("secret"))
	symBlob, _ := encryptlocal.Encrypt(symKey, []byte("secret"))

	// Symmetric Decrypt rejects an escrow blob; DecryptEscrow rejects a sym blob.
	if _, err := encryptlocal.Decrypt(symKey, escrowBlob); err == nil {
		t.Error("symmetric Decrypt accepted an escrow blob")
	}
	if _, err := encryptlocal.DecryptEscrow(pub, priv, symBlob); err == nil {
		t.Error("DecryptEscrow accepted a symmetric blob")
	}

	// Escrow re-encryption is idempotent (already-encrypted → no-op).
	dir := t.TempDir()
	f := filepath.Join(dir, "d.txt")
	_ = os.WriteFile(f, []byte("data"), 0o600)
	enf, _ := encryptlocal.WithEscrowKey(pub)
	dec := &corev1.Decision{Action: corev1.Action_ACTION_ENCRYPT_LOCAL}
	_ = enf.EnforceTarget(context.Background(), dec, f)
	first, _ := os.ReadFile(f)
	_ = enf.EnforceTarget(context.Background(), dec, f)
	second, _ := os.ReadFile(f)
	if !bytes.Equal(first, second) {
		t.Fatal("escrow re-encryption was not idempotent")
	}
	got, err := encryptlocal.DecryptEscrow(pub, priv, second)
	if err != nil || string(got) != "data" {
		t.Fatalf("re-encrypted escrow file did not recover: %v", err)
	}
}

// 3.3 — a wrong-length public key is rejected, and an empty target errors.
func TestEscrowKeyLengthAndEmptyTarget(t *testing.T) {
	if _, err := encryptlocal.WithEscrowKey([]byte("short")); err == nil {
		t.Error("a short escrow public key was accepted")
	}
	pub, _, _ := encryptlocal.GenerateEscrowKeypair()
	enf, _ := encryptlocal.WithEscrowKey(pub)
	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{}, ""); err == nil {
		t.Error("empty target did not error in escrow mode")
	}
}
