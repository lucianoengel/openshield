package engine_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

// End to end: a policy deciding ENCRYPT_LOCAL routes to the registered
// encrypt-local enforcer, the flagged file ends up ENCRYPTED on disk (recoverable
// with the key), and the enforcement outcome is audited (D14/D57). Decision is
// recorded before enforcement.
func TestEncryptLocalDispatchedAndAudited(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "leak.csv")
	plaintext := []byte("cpf,name\n111.444.777-35,bob\n")
	if err := os.WriteFile(target, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, encryptlocal.KeySize)
	for i := range key {
		key[i] = 0x5a
	}
	enf, err := encryptlocal.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}

	led := &recLedger{}
	e := engineWith(led, corev1.Action_ACTION_ENCRYPT_LOCAL, enf)

	if _, err := e.Process(context.Background(), fsEvent("e1", target)); err != nil {
		t.Fatal(err)
	}

	// The file is encrypted in place: on-disk bytes differ, plaintext is gone,
	// and it recovers with the key.
	onDisk, _ := os.ReadFile(target)
	if bytes.Equal(onDisk, plaintext) || bytes.Contains(onDisk, []byte("bob")) {
		t.Fatal("the flagged file was not encrypted on disk")
	}
	got, err := encryptlocal.Decrypt(key, onDisk)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("encrypted file does not recover to the original: %v", err)
	}

	// Decision recorded, then the enforcement outcome (never silent, D14).
	if len(led.entries) != 2 {
		t.Fatalf("entries = %d, want 2 (decision then enforcement)", len(led.entries))
	}
	if led.entries[0].OutcomeKind == "enforced" {
		t.Error("enforcement recorded before the decision")
	}
	if led.entries[1].OutcomeKind != "enforced" {
		t.Errorf("second entry = %q, want 'enforced'", led.entries[1].OutcomeKind)
	}
}

// End to end in ESCROW mode (D59): a policy deciding ENCRYPT_LOCAL routes to an
// escrow enforcer holding only the recipient PUBLIC key; the file is sealed so
// the endpoint cannot decrypt it, only the off-endpoint PRIVATE key recovers it,
// and the outcome is audited.
func TestEncryptLocalEscrowDispatchedAndAudited(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "leak.csv")
	plaintext := []byte("cpf,name\n111.444.777-35,dave\n")
	if err := os.WriteFile(target, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := encryptlocal.GenerateEscrowKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enf, err := encryptlocal.WithEscrowKey(pub) // engine/endpoint holds only pub
	if err != nil {
		t.Fatal(err)
	}

	led := &recLedger{}
	e := engineWith(led, corev1.Action_ACTION_ENCRYPT_LOCAL, enf)
	if _, err := e.Process(context.Background(), fsEvent("e1", target)); err != nil {
		t.Fatal(err)
	}

	onDisk, _ := os.ReadFile(target)
	if bytes.Equal(onDisk, plaintext) || bytes.Contains(onDisk, []byte("dave")) {
		t.Fatal("the flagged file was not sealed")
	}
	// Only the escrow PRIVATE key recovers it.
	got, err := encryptlocal.DecryptEscrow(pub, priv, onDisk)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("escrow file does not recover with the private key: %v", err)
	}
	if len(led.entries) != 2 || led.entries[1].OutcomeKind != "enforced" {
		t.Fatalf("expected decision + enforced audit, got %d entries", len(led.entries))
	}
}
