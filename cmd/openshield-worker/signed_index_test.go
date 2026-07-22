package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
)

// writeSignedEDM writes a signed EDM index + its public key to dir, returning both paths and the
// seeded value.
func writeSignedEDM(t *testing.T, dir string) (idxPath, pubPath, secret string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret = "4111111111111111"
	idx := classify.NewEDMIndex(0.001, 4)
	idx.Add(secret)
	signed, err := classify.SignIndex(classify.IndexKindEDM, idx.Marshal(), priv)
	if err != nil {
		t.Fatal(err)
	}
	idxPath = filepath.Join(dir, "edm.signed")
	pubPath = filepath.Join(dir, "operator.pub")
	if err := os.WriteFile(idxPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return idxPath, pubPath, secret
}

// TestWorkerLoadsSignedIndex (DLP-3/ADR-9): with the operator key configured, loadIndexBytes VERIFIES
// then returns the index bytes, which load and detect the seeded value — the worker's real path.
func TestWorkerLoadsSignedIndex(t *testing.T) {
	dir := t.TempDir()
	idxPath, pubPath, secret := writeSignedEDM(t, dir)
	t.Setenv("OPENSHIELD_DLP_INDEX_PUBKEY", pubPath)

	pub := loadIndexPubKey()
	if pub == nil {
		t.Fatal("loadIndexPubKey returned nil despite a configured key")
	}
	blob := loadIndexBytes(idxPath, classify.IndexKindEDM, pub)
	idx, err := classify.LoadEDMIndex(blob)
	if err != nil {
		t.Fatalf("verified index did not load: %v", err)
	}
	if !idx.Contains(secret) {
		t.Fatal("the worker-loaded signed index does not detect the seeded value")
	}
}

// TestWorkerAbortsOnUnverifiedIndex (DLP-3/ADR-9, fail-closed): with the operator key configured, an
// UNSIGNED index file must abort the worker (os.Exit), never load unverified. Uses the standard
// re-exec-the-test pattern to observe the exit.
//
// Mutation: if loadIndexBytes loaded the file without verifying under a set key, the child would exit
// 0 and this test FAILs.
func TestWorkerAbortsOnUnverifiedIndex(t *testing.T) {
	if os.Getenv("OPENSHIELD_WORKER_ABORT_CHILD") == "1" {
		// Child: a configured key + an UNSIGNED file → loadIndexBytes must os.Exit(1).
		pub := loadIndexPubKey()
		loadIndexBytes(os.Getenv("OPENSHIELD_TEST_IDX_FILE"), classify.IndexKindEDM, pub)
		return // reaching here means it loaded unverified — the mutation
	}
	dir := t.TempDir()
	_, pubPath, _ := writeSignedEDM(t, dir)
	// An UNSIGNED (raw) index file — valid bytes, but not a signed envelope.
	unsigned := classify.NewEDMIndex(0.001, 2)
	unsigned.Add("x")
	unsignedPath := filepath.Join(dir, "raw.idx")
	if err := os.WriteFile(unsignedPath, unsigned.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestWorkerAbortsOnUnverifiedIndex")
	cmd.Env = append(os.Environ(),
		"OPENSHIELD_WORKER_ABORT_CHILD=1",
		"OPENSHIELD_DLP_INDEX_PUBKEY="+pubPath,
		"OPENSHIELD_TEST_IDX_FILE="+unsignedPath,
	)
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.Success() {
		t.Fatalf("worker did not abort on an unsigned index under a configured key (err=%v) — it loaded unverified", err)
	}
}
