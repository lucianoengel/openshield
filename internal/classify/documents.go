package classify

import (
	"archive/zip"
	"bytes"
	"io"
	"regexp"
	"strings"
)

// Document-structure extraction (Phase D1). Office documents (DOCX/XLSX/PPTX) are ZIP
// containers of XML — so a CPF inside a .docx is invisible to a detector that scans the
// raw bytes (it sees deflate-compressed noise). This layer, run BEFORE the detectors,
// unzips a recognized OOXML container and pulls out its text, so the SAME detectors then
// see the real content. It is exactly the parser surface the sandbox split was built for
// (D29/D35): it runs in the seccomp worker, never in the privileged agent.
//
// It is bounded against a decompression bomb (D13): the worker already caps the RAW input
// (8 MiB), and this caps the EXPANDED output and the entry count — a 4 KB zip that expands
// to gigabytes hits maxExtractBytes and stops, rather than exhausting memory.

const (
	// maxExtractBytes caps total extracted text. The raw input is already bounded by the
	// worker; this bounds the expansion so a zip bomb cannot blow past it.
	maxExtractBytes = 16 << 20 // 16 MiB
	// maxZipEntries caps how many members we will even look at — a zip with a million
	// tiny entries is itself an exhaustion vector.
	maxZipEntries = 4096
	// maxEntryBytes caps a single member's expansion.
	maxEntryBytes = 8 << 20
)

// zipMagic is the local-file-header signature that starts every ZIP (and thus every
// OOXML document). A cheap prefix check avoids handing non-zip bytes to zip.NewReader.
var zipMagic = []byte{'P', 'K', 0x03, 0x04}

// ooxmlTextEntry matches the archive members that carry user text across DOCX (word/…),
// XLSX (xl/sharedStrings, xl/worksheets/…) and PPTX (ppt/slides/…). Chrome/media/rels
// members are skipped — they hold no user content and only cost expansion budget.
var ooxmlTextEntry = regexp.MustCompile(`^(word/.*\.xml|xl/sharedStrings\.xml|xl/worksheets/.*\.xml|ppt/slides/.*\.xml)$`)

// xmlTag strips XML markup so the detectors see text, not angle-bracket noise.
var xmlTag = regexp.MustCompile(`<[^>]*>`)

// extractOOXML returns the concatenated text of a recognized Office document, or
// (nil, false) if data is not an OOXML container the extractor handles. A non-zip input,
// a zip with no recognized text members, or a corrupt archive all return false — the
// caller then scans the raw bytes, so a mis-detection degrades to "scan as-is", never to
// "scan nothing".
func extractOOXML(data []byte) ([]byte, bool) {
	if len(data) < len(zipMagic) || !bytes.Equal(data[:len(zipMagic)], zipMagic) {
		return nil, false
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}

	var out bytes.Buffer
	budget := int64(maxExtractBytes)
	matched := false
	for i, f := range zr.File {
		if i >= maxZipEntries || budget <= 0 {
			break
		}
		if !ooxmlTextEntry.MatchString(f.Name) {
			continue
		}
		matched = true
		text := readEntryText(f, min64(budget, maxEntryBytes))
		budget -= int64(len(text))
		out.WriteString(text)
		out.WriteByte(' ')
	}
	if !matched {
		return nil, false
	}
	return out.Bytes(), true
}

// readEntryText opens one archive member, reads up to limit bytes of it, and strips XML
// markup. A member that fails to open or read yields "" — one bad member never fails the
// whole extraction (best-effort, like the raw-scan fallback).
func readEntryText(f *zip.File, limit int64) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return ""
	}
	stripped := xmlTag.ReplaceAll(raw, []byte(" "))
	return strings.TrimSpace(string(stripped))
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
