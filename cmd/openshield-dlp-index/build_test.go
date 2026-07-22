package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
)

// TestBuildEDMSignsAndDetects (DLP-3/ADR-9, tool→worker round-trip): the operator tool's EDM build
// produces an index whose bytes, once signed, VERIFY with the worker's VerifyIndex AND detect the
// operator's seeded value — the exact path the worker runs.
func TestBuildEDMSignsAndDetects(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "values.txt")
	const secret = "4111111111111111"
	if err := os.WriteFile(in, []byte(secret+"\nAKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	indexBytes := buildEDM(in, 0.001)
	signed, err := classify.SignIndex(classify.IndexKindEDM, indexBytes, priv)
	if err != nil {
		t.Fatalf("SignIndex: %v", err)
	}
	// The worker's verification path.
	verified, err := classify.VerifyIndex(signed, pub, classify.IndexKindEDM)
	if err != nil {
		t.Fatalf("the tool's signed EDM index did not verify: %v", err)
	}
	idx, err := classify.LoadEDMIndex(verified)
	if err != nil {
		t.Fatalf("verified EDM bytes did not load: %v", err)
	}
	if !idx.Contains(secret) {
		t.Fatal("the tool-built EDM index does not detect the operator's seeded value")
	}
}

// TestBuildRecordAndIDMProduceLoadableIndexes (DLP-3): the record and IDM builders produce non-empty,
// loadable indexes from operator input, and their signed form verifies+loads (round-trip).
func TestBuildRecordAndIDMProduceLoadableIndexes(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Record: two distinctive cells per row so BuildRecordIndex keeps the record.
	recFile := filepath.Join(dir, "records.tsv")
	if err := os.WriteFile(recFile, []byte("John Q Patient\t123-45-6789\tACCT-99881\nJane R Client\t987-65-4321\tACCT-55217\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recBytes := buildRecord(recFile, "\t", 2)
	recSigned, _ := classify.SignIndex(classify.IndexKindRecord, recBytes, priv)
	if v, err := classify.VerifyIndex(recSigned, pub, classify.IndexKindRecord); err != nil {
		t.Fatalf("record index verify: %v", err)
	} else if _, err := classify.LoadRecordIndex(v); err != nil {
		t.Fatalf("record index load: %v", err)
	}

	// IDM: a directory with one document file long enough to yield shingles.
	docDir := filepath.Join(dir, "docs")
	if err := os.Mkdir(docDir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := "This confidential memorandum describes the acquisition strategy and the internal " +
		"valuation model that must not leave the finance department under any circumstances whatsoever."
	if err := os.WriteFile(filepath.Join(docDir, "memo.txt"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	idmBytes := buildIDM(docDir, 0.3)
	idmSigned, _ := classify.SignIndex(classify.IndexKindIDM, idmBytes, priv)
	if v, err := classify.VerifyIndex(idmSigned, pub, classify.IndexKindIDM); err != nil {
		t.Fatalf("idm index verify: %v", err)
	} else if _, err := classify.LoadDocumentIndex(v); err != nil {
		t.Fatalf("idm index load: %v", err)
	}
}
