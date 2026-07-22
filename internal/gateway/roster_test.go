package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// SEC-12 + IDENT-1: LoadPostureRoster parses a "<agent-identity> <base64-pubkey>" file into a
// resolver keyed by the CANONICAL pseudonym (so it matches the subject the publisher signs and the
// proxy resolves), and rejects a malformed line or a bad key rather than silently loading a partial
// roster.
func TestLoadPostureRoster(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	good := filepath.Join(dir, "roster")
	os.WriteFile(good, []byte("# a comment\n\nagent-A "+base64.StdEncoding.EncodeToString(pubA)+"\n"), 0o600)

	resolve, err := gateway.LoadPostureRoster(good)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The roster lists the human identity "agent-A"; it resolves under the canonical pseudonym
	// (what an incoming posture update carries), NOT the raw identity.
	if k, ok := resolve(pseudonym.Of("agent-A")); !ok || string(k) != string(pubA) {
		t.Errorf("agent-A key not resolved under its canonical pseudonym")
	}
	if _, ok := resolve("agent-A"); ok {
		t.Errorf("the raw identity resolved to a key — the roster must key by the canonical pseudonym")
	}
	if _, ok := resolve(pseudonym.Of("agent-Z")); ok {
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
