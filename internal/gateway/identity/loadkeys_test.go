package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// ZT-2: LoadOIDCKeys reads a directory of <kid>.pem public keys into a kid->key map; a non-PEM file
// errors, and an empty directory errors (a verifier with no keys would verify nothing).
func TestLoadOIDCKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "kid-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600) // non-.pem ignored

	keys, err := identity.LoadOIDCKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["kid-1"]; !ok || len(keys) != 1 {
		t.Errorf("keys = %v, want exactly kid-1", keys)
	}

	// A bad PEM errors.
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "x.pem"), []byte("not pem"), 0o600)
	if _, err := identity.LoadOIDCKeys(bad); err == nil {
		t.Error("a non-PEM key file was accepted")
	}
	// An empty dir errors.
	if _, err := identity.LoadOIDCKeys(t.TempDir()); err == nil {
		t.Error("an empty key directory was accepted")
	}
}
