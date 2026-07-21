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

// 3.2 — a target swapped for a SYMLINK to a secret (the classification→enforce
// TOCTOU) is REFUSED: encryptlocal neither reads the secret nor writes an
// encrypted blob over the symlink (D65).
func TestEncryptRefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "flagged") // was a regular file; now a symlink
	if err := os.Symlink(secret, target); err != nil {
		t.Fatal(err)
	}

	enf, _ := encryptlocal.WithKey(bytes.Repeat([]byte{1}, encryptlocal.KeySize))
	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{}, target); err == nil {
		t.Fatal("encryptlocal followed a symlink target and did not refuse")
	}

	// The secret's content is untouched (never read, never encrypted).
	got, _ := os.ReadFile(secret)
	if !bytes.Equal(got, []byte("TOPSECRET")) {
		t.Fatal("the symlink's destination was modified")
	}
	// The target is still a symlink — not replaced by an encrypted blob.
	fi, err := os.Lstat(target)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink target was replaced by the enforcer")
	}
}
