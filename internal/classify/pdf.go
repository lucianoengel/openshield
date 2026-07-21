package classify

import (
	"bytes"
	"io"

	"github.com/ledongthuc/pdf"
)

// PDF text extraction (Phase D1, second format after OOXML). A PDF is a structured binary
// container; its text is compressed inside content streams, invisible to a byte-level
// detector. This pulls the plain text so the SAME detectors see it. Like OOXML extraction
// it runs in the seccomp worker (D29/D35) — exactly the RCE surface the split was built
// for — and NEVER in the privileged agent (D72).
//
// A PDF parser on hostile input is the canonical crash/DoS surface (cf. the ClamAV PDF
// CVE that motivated the sandbox). Two defenses beyond the sandbox: the extracted text is
// bounded (maxExtractBytes), and the parse is wrapped in a recover — a malformed PDF that
// panics the parser degrades to a raw scan, never a crash of the classifier.

// pdfMagic starts every PDF ("%PDF-"). A cheap prefix check avoids handing non-PDF bytes
// to the parser.
var pdfMagic = []byte("%PDF-")

// extractPDF returns the plain text of a PDF, or (nil, false) if data is not a PDF or the
// parse fails/panics. A failure falls back to a raw scan (never "scan nothing").
func extractPDF(data []byte) (out []byte, ok bool) {
	if len(data) < len(pdfMagic) || !bytes.Equal(data[:len(pdfMagic)], pdfMagic) {
		return nil, false
	}
	// The parser can panic on malformed input; contain it here so a hostile PDF cannot
	// crash classification — it just falls through to the raw-byte scan.
	defer func() {
		if r := recover(); r != nil {
			out, ok = nil, false
		}
	}()

	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	tr, err := r.GetPlainText()
	if err != nil {
		return nil, false
	}
	text, err := io.ReadAll(io.LimitReader(tr, maxExtractBytes))
	if err != nil || len(text) == 0 {
		return nil, false
	}
	return text, true
}
