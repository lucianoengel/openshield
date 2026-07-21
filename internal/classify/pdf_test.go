package classify_test

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// buildMinimalPDF assembles a byte-valid single-page PDF whose content stream draws the
// given text, COMPRESSED with FlateDecode, computing the cross-reference offsets so the
// parser accepts it. Compression is deliberate: it means the text is NOT present verbatim
// in the raw bytes, so a passing detection PROVES the PDF was actually parsed and
// decompressed — not that the raw-scan fallback happened to see the plaintext.
func buildMinimalPDF(t *testing.T, text string) []byte {
	t.Helper()
	plain := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", text)
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write([]byte(plain))
	zw.Close()
	stream := zbuf.Bytes()
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs)+1)
	for i, body := range objs {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xrefOff := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n", len(objs)+1)
	b.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&b, "trailer\n<< /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xrefOff)
	return b.Bytes()
}

// A CPF inside a real PDF is detected — Phase D1 for PDFs. Without extraction the detector
// would scan the PDF's binary structure and miss it.
func TestClassifyExtractsPDF(t *testing.T) {
	pdf := buildMinimalPDF(t, "customer CPF 111.444.777-35 on record")
	// Guard the guard: the CPF must NOT be in the raw bytes, so a hit can only come from
	// real PDF parsing + decompression, not the raw-scan fallback.
	if bytes.Contains(pdf, []byte("111.444.777-35")) {
		t.Fatal("test setup wrong: the CPF is present verbatim in the raw PDF bytes")
	}
	if !hasType(classifyBytes(t, pdf), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a CPF inside a PDF was not detected — PDF extraction failed")
	}
}

// A malformed PDF (the %PDF- magic but garbage body) must NOT crash the classifier — the
// parser panic/error is contained and it falls back to a raw scan. The CPF that sits
// verbatim in the raw bytes is then still found via the fallback.
func TestClassifyMalformedPDFDoesNotCrash(t *testing.T) {
	malformed := append([]byte("%PDF-1.4\n"), []byte("garbage not a real pdf CPF 111.444.777-35 \x00\x01\x02")...)
	// Must not panic; the raw-scan fallback still finds the plainly-visible CPF.
	if !hasType(classifyBytes(t, malformed), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("malformed PDF: the raw-scan fallback did not find the visible CPF")
	}
}
