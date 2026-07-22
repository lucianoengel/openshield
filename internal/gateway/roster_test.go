package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// SEC-12: LoadPostureRoster parses a "<subject> <base64-pubkey>" file into a resolver, and rejects a
// malformed line or a bad key rather than silently loading a partial roster.
func TestLoadPostureRoster(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	good := filepath.Join(dir, "roster")
	os.WriteFile(good, []byte("# a comment\n\nagent-A "+base64.StdEncoding.EncodeToString(pubA)+"\n"), 0o600)

	resolve, err := gateway.LoadPostureRoster(good)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if k, ok := resolve("agent-A"); !ok || string(k) != string(pubA) {
		t.Errorf("agent-A key not resolved")
	}
	if _, ok := resolve("agent-Z"); ok {
		t.Errorf("an unlisted subject resolved to a key")
	}

	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("agent-A not-base64!!\n"), 0o600)
	if _, err := gateway.LoadPostureRoster(bad); err == nil {
		t.Error("a bad pubkey in the roster was accepted")
	}
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("# only comments\n"), 0o600)
	if _, err := gateway.LoadPostureRoster(empty); err == nil {
		t.Error("an empty roster was accepted")
	}
}
