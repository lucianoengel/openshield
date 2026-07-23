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
	// maxArchiveDepth caps nested-archive recursion (DLP-8): a zip-in-a-zip-in-a-… beyond this is
	// scanned as-is rather than expanded — 5 levels is generous for legitimate content, and it
	// guarantees termination independent of the byte budget.
	maxArchiveDepth = 4
)

// extractContent recursively extracts scannable text from a container so the detectors see the real
// content (DLP-8). It tries, in order, a recognized Office doc (clean OOXML text), a PDF, then a GENERAL
// ZIP (every member — recursing a member that is itself a container). A non-container returns its own
// bytes (scan as-is). budget is a SHARED byte ceiling decremented across the WHOLE recursion, so a
// zip-bomb nested inside a zip cannot amplify per level; depth bounds nesting. This runs in the seccomp
// worker (D29/D35), never in the privileged agent.
func extractContent(data []byte, depth int, budget *int64) []byte {
	if *budget <= 0 || depth > maxArchiveDepth {
		return data
	}
	// OOXML BEFORE the general zip: an Office doc is a zip, and extractOOXML yields clean XML-stripped
	// text where the general path would dump raw XML. (extractOOXML/extractPDF have their own internal
	// expansion caps; the shared budget is decremented at each zip-member READ in extractZipArchive.)
	if t, ok := extractOOXML(data); ok {
		return t
	}
	if t, ok := extractPDF(data); ok {
		return t
	}
	if t, ok := extractZipArchive(data, depth, budget); ok {
		return t
	}
	return data
}

// extractZipArchive extracts EVERY member of a general ZIP (not just OOXML text members), recursing
// each member through extractContent so a sensitive file in a plain zip — or nested in a zip-in-a-zip —
// is classified. Bounded by the shared budget, the entry cap, and depth. Best-effort per member (a bad
// member is skipped, never failing the whole extraction). Returns (nil,false) for a non-zip so the
// caller falls back to a raw scan.
func extractZipArchive(data []byte, depth int, budget *int64) ([]byte, bool) {
	if len(data) < len(zipMagic) || !bytes.Equal(data[:len(zipMagic)], zipMagic) {
		return nil, false
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	var out bytes.Buffer
	for i, f := range zr.File {
		if i >= maxZipEntries || *budget <= 0 {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue // one unreadable member never fails the whole extraction
		}
		raw, err := io.ReadAll(io.LimitReader(rc, min64(*budget, maxEntryBytes)))
		rc.Close()
		if err != nil {
			continue
		}
		*budget -= int64(len(raw)) // every byte READ from a member is charged to the shared ceiling,
		// so a bomb nested inside a zip cannot amplify the budget per level.
		extracted := extractContent(raw, depth+1, budget) // recurse: a member may itself be a container
		out.Write(extracted)
		out.WriteByte(' ')
	}
	return out.Bytes(), true
}

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
