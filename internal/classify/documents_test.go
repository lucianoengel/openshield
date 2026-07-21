package classify_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// buildOOXML assembles a minimal but genuine OOXML zip: a set of {entry-name → XML}
// members. Uses archive/zip so the extractor exercises a REAL deflate stream, not a stub.
func buildOOXML(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func classifyBytes(t *testing.T, data []byte) []*corev1.DetectorHit {
	t.Helper()
	hits, err := classify.New().Classify(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func hasType(hits []*corev1.DetectorHit, want corev1.DetectorType) bool {
	for _, h := range hits {
		if h.GetDetectorType() == want {
			return true
		}
	}
	return false
}

// A CPF hidden inside a .docx is detected — the whole point of D1. Without extraction the
// detector would scan compressed noise and miss it.
func TestClassifyExtractsDOCX(t *testing.T) {
	docx := buildOOXML(t, map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types/>`,
		"word/document.xml": `<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>` +
			`customer CPF 111.444.777-35 on file</w:t></w:r></w:p></w:body></w:document>`,
	})
	if !hasType(classifyBytes(t, docx), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a CPF inside a .docx was not detected — document extraction failed")
	}
}

// A secret inside an .xlsx shared-strings table is detected too (D96 detectors over D1
// extraction — the layers compose).
func TestClassifyExtractsXLSXSecret(t *testing.T) {
	xlsx := buildOOXML(t, map[string]string{
		"xl/sharedStrings.xml": `<?xml version="1.0"?><sst><si><t>` +
			`token ghp_` + strings.Repeat("a", 36) + `</t></si></sst>`,
	})
	if !hasType(classifyBytes(t, xlsx), corev1.DetectorType_DETECTOR_TYPE_API_TOKEN) {
		t.Error("a token inside an .xlsx was not detected")
	}
}

// A plain-text file with a CPF still works — extraction returns false and the raw bytes
// are scanned (the fallback path, so extraction never breaks non-documents).
func TestClassifyPlainTextStillWorks(t *testing.T) {
	if !hasType(classifyBytes(t, []byte("name,cpf\nalice,111.444.777-35\n")), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a CPF in plain text was not detected — the raw-scan fallback broke")
	}
}

// A zip that is NOT an OOXML document (no recognized text members) falls through to a raw
// scan — and a CPF that happens to sit in a stored (uncompressed) member is still found
// via the raw bytes, proving the fallback does not silently drop content.
func TestClassifyNonOOXMLZipFallsBackToRawScan(t *testing.T) {
	// A zip whose only member is not an OOXML text entry, STORED (not deflated) so the
	// CPF appears verbatim in the raw bytes.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "notes.txt", Method: zip.Store})
	w.Write([]byte("cpf 111.444.777-35"))
	zw.Close()
	if !hasType(classifyBytes(t, buf.Bytes()), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a CPF in a stored zip member was not found by the raw-scan fallback")
	}
}

// The per-entry extraction bound is REAL and observable: a CPF placed PAST the per-entry
// ceiling (8 MiB) is not extracted, so it is not detected — proving the LimitReader
// actually bounds the read (a mutation that removes it would read the whole member and
// find the CPF). The deep hit is left to no one here — this is the honest limit of
// bounded extraction, mirroring the prefilter's prefix bound.
func TestClassifyExtractionEntryBoundIsReal(t *testing.T) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0"?><w:document><w:body><w:t>`)
	body.WriteString(strings.Repeat("x", 9<<20)) // 9 MiB of filler, past the 8 MiB cap
	body.WriteString(`CPF 111.444.777-35`)
	body.WriteString(`</w:t></w:body></w:document>`)
	docx := buildOOXML(t, map[string]string{"word/document.xml": body.String()})
	if hasType(classifyBytes(t, docx), corev1.DetectorType_DETECTOR_TYPE_CPF) {
		t.Error("a CPF past the per-entry extract ceiling was found — the read is unbounded")
	}
}

// Decompression-bomb defense (D13): a highly compressible document member that expands
// far beyond the extract ceiling must not exhaust memory — extraction is bounded and
// simply returns (classification does not hang or OOM). We assert it TERMINATES and stays
// bounded, not any particular hit.
func TestClassifyBoundsDecompressionBomb(t *testing.T) {
	// Craft a word/document.xml entry whose uncompressed size is ~64 MiB of one byte —
	// well past maxExtractBytes (16 MiB) — using a hand-built deflate stream so the zip
	// stays tiny on disk.
	huge := bytes.Repeat([]byte("A"), 64<<20)
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.BestCompression)
	fw.Write(huge)
	fw.Close()

	zipBytes := buildRawZip(t, "word/document.xml", comp.Bytes(), uint64(len(huge)))
	// Must return within the test timeout and not OOM; a hit is not required.
	done := make(chan struct{})
	go func() {
		_, err := classify.New().Classify(context.Background(), bytes.NewReader(zipBytes))
		if err != nil {
			t.Errorf("bomb classification errored: %v", err)
		}
		close(done)
	}()
	<-done
}

// buildRawZip writes a single-member zip with a pre-deflated payload, so a tiny archive
// declares a huge uncompressed size (the decompression-bomb shape).
func buildRawZip(t *testing.T, name string, deflated []byte, uncompressedSize uint64) []byte {
	t.Helper()
	crc := crc32IEEE([]byte(strings.Repeat("A", int(uncompressedSize))))
	var b bytes.Buffer
	// Local file header.
	b.Write([]byte{'P', 'K', 0x03, 0x04})
	le16(&b, 20)                       // version
	le16(&b, 0)                        // flags
	le16(&b, 8)                        // method = deflate
	le16(&b, 0)                        // modtime
	le16(&b, 0)                        // moddate
	le32(&b, crc)                      // crc32
	le32(&b, uint32(len(deflated)))    // compressed size
	le32(&b, uint32(uncompressedSize)) // uncompressed size
	le16(&b, uint16(len(name)))        // name length
	le16(&b, 0)                        // extra length
	b.WriteString(name)
	localHeaderOff := 0
	b.Write(deflated)
	// Central directory.
	cdStart := b.Len()
	b.Write([]byte{'P', 'K', 0x01, 0x02})
	le16(&b, 20)
	le16(&b, 20)
	le16(&b, 0)
	le16(&b, 8)
	le16(&b, 0)
	le16(&b, 0)
	le32(&b, crc)
	le32(&b, uint32(len(deflated)))
	le32(&b, uint32(uncompressedSize))
	le16(&b, uint16(len(name)))
	le16(&b, 0)
	le16(&b, 0)
	le16(&b, 0)
	le16(&b, 0)
	le32(&b, 0)
	le32(&b, uint32(localHeaderOff))
	b.WriteString(name)
	cdEnd := b.Len()
	// End of central directory.
	b.Write([]byte{'P', 'K', 0x05, 0x06})
	le16(&b, 0)
	le16(&b, 0)
	le16(&b, 1)
	le16(&b, 1)
	le32(&b, uint32(cdEnd-cdStart))
	le32(&b, uint32(cdStart))
	le16(&b, 0)
	return b.Bytes()
}

func le16(b *bytes.Buffer, v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	b.Write(t[:])
}
func le32(b *bytes.Buffer, v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	b.Write(t[:])
}

func crc32IEEE(p []byte) uint32 {
	var crc uint32 = 0xffffffff
	for _, b := range p {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xffffffff
}
