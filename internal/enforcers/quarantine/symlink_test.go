package quarantine_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
)

// 3.3 — quarantine refuses a symlink source (the TOCTOU) rather than moving the
// link or copying an attacker-chosen file into the owner-only quarantine dir (D65).
func TestQuarantineRefusesSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "flagged")
	if err := os.Symlink(secret, src); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")

	enf := quarantine.New(qdir)
	if err := enf.EnforceTarget(context.Background(),
		&corev1.Decision{Action: corev1.Action_ACTION_QUARANTINE_LOCAL}, src); err == nil {
		t.Fatal("quarantine acted on a symlink source and did not refuse")
	}

	// Nothing containing the secret ended up in quarantine.
	if entries, _ := os.ReadDir(qdir); len(entries) > 0 {
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(qdir, e.Name()))
			if bytes.Contains(b, []byte("TOPSECRET")) {
				t.Fatal("the secret was copied into quarantine")
			}
		}
	}
	got, _ := os.ReadFile(secret)
	if !bytes.Equal(got, []byte("TOPSECRET")) {
		t.Fatal("the secret was modified")
	}
}
