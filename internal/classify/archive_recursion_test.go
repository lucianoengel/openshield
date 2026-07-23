package classify_test

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// zipDeflated builds a zip with one DEFLATED member (name → body). Deflate matters: the plaintext does
// NOT appear in the raw bytes, so a hit proves EXTRACTION found it (not the raw-scan fallback).
func zipDeflated(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name) // Create defaults to Deflate
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestClassifyExtractsFileInPlainZip (DLP-8): a sensitive value in a plain-text file inside a ZIP is
// detected. The member is DEFLATED, so before this change the classifier scanned compressed noise and
// missed it — the double-zip-style evasion.
//
// Mutation: if extractZipArchive did not extract members (returned raw), the deflated CPF would be
// invisible → no hit → FAIL.
func TestClassifyExtractsFileInPlainZip(t *testing.T) {
	z := zipDeflated(t, "secrets.txt", "customer CPF 111.444.777-35 exfiltrated")
	hits, err := classify.New().Classify(context.Background(), bytes.NewReader(z))
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(hits, corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Fatal("a CPF in a deflated file inside a plain zip was not detected — archive content is a blind spot")
	}
}

// TestClassifyExtractsDoubleZip (DLP-8): the sensitive file DOUBLE-zipped (a zip inside a zip) is still
// detected — nested-archive recursion.
//
// Mutation: setting the depth cap to 0 (no recursion) leaves the inner zip's compressed bytes
// unextracted → no hit → FAIL.
func TestClassifyExtractsDoubleZip(t *testing.T) {
	inner := zipDeflated(t, "secrets.txt", "customer CPF 111.444.777-35 exfiltrated")
	// Wrap the inner zip as a member of an outer zip, deflated.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("inner.zip")
	w.Write(inner)
	zw.Close()

	hits, err := classify.New().Classify(context.Background(), bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(hits, corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Fatal("a CPF double-zipped was not detected — nested-archive recursion missing")
	}
}

// TestClassifyExtractsDocxInsideZip (DLP-8): a .docx inside a .zip yields its OOXML text (the member
// hits the OOXML branch during recursion).
func TestClassifyExtractsDocxInsideZip(t *testing.T) {
	docx := buildOOXML(t, map[string]string{
		"word/document.xml": `<?xml version="1.0"?><w:document><w:body><w:t>CPF 111.444.777-35</w:t></w:body></w:document>`,
	})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("report.docx")
	w.Write(docx)
	zw.Close()

	if !hasType(classifyBytes(t, buf.Bytes()), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Fatal("a .docx inside a .zip did not yield its OOXML text")
	}
}

// TestClassifyDeepNestingIsBounded (DLP-8): a DEEPLY-nested archive (a zip in a zip in a zip …, the
// recursive-decompression amplification vector) does not recurse without limit — the depth cap stops
// it, so classification completes fast. The value at the deepest level (past the cap) is NOT extracted,
// which is the honest bound; the test's assertion is that classification RETURNS bounded.
func TestClassifyDeepNestingIsBounded(t *testing.T) {
	// Innermost payload, then wrap it 12 times — well past maxArchiveDepth (4).
	cur := []byte("customer CPF 111.444.777-35 deep inside")
	for i := 0; i < 12; i++ {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("nested.zip")
		w.Write(cur)
		zw.Close()
		cur = buf.Bytes()
	}
	// Must complete (no unbounded recursion / hang) — extraction stops at the depth cap.
	if _, err := classify.New().Classify(context.Background(), bytes.NewReader(cur)); err != nil {
		t.Fatalf("classify errored on a deeply-nested archive: %v", err)
	}
	// A payload within the depth cap IS reached, confirming recursion actually runs (not disabled).
	shallow := []byte("customer CPF 111.444.777-35")
	for i := 0; i < 3; i++ { // 3 wraps → depths 1..3, within the cap
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("n.zip")
		w.Write(shallow)
		zw.Close()
		shallow = buf.Bytes()
	}
	if !hasType(classifyBytes(t, shallow), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Fatal("a CPF nested within the depth cap was not detected — recursion is not reaching it")
	}
}
