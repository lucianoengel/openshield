package classify

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

const confidentialDoc = `CONFIDENTIAL MERGER AGREEMENT between Acme Corporation and Beta Industries.
The parties agree to combine operations effective the first quarter, with Acme acquiring all outstanding
shares of Beta at a price of forty two dollars per share, subject to regulatory approval and shareholder
ratification. This agreement contains material non public information and must not be disclosed.`

const unrelatedDoc = `The quick brown fox jumps over the lazy dog near the riverbank while the sun sets slowly
behind the distant mountains and the evening breeze carries the scent of pine across the quiet valley below.`

func docIndex(t *testing.T) *DocumentIndex {
	t.Helper()
	idx, skipped := BuildDocumentIndex([]string{confidentialDoc, unrelatedDoc}, DefaultShingleK, 0.3)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	return idx
}

func TestIDMMatchesExcerptTolerantOfReformat(t *testing.T) {
	det := idm{index: docIndex(t)}

	// A reformatted excerpt (different whitespace/casing/punctuation) covering a big
	// chunk of the confidential doc → a match.
	excerpt := "acme acquiring all outstanding shares of beta at a price of forty two dollars per share, " +
		"subject to regulatory approval and shareholder ratification; this agreement contains material non public information"
	if n, _ := det.Scan([]byte(excerpt)); n != 1 {
		t.Fatalf("reformatted excerpt = %d, want 1 (document match)", n)
	}

	// A short snippet that DOES produce a few shingles (≥ k words) but far fewer than
	// the 0.3 fraction of the document's shingles → NO match. (This is the case that
	// distinguishes the fraction threshold from "any shingle matches".)
	snippet := "subject to regulatory approval and shareholder ratification"
	if n, _ := det.Scan([]byte(snippet)); n != 0 {
		t.Fatalf("below-fraction snippet = %d, want 0 (below the fraction)", n)
	}

	// Unrelated text → NO match.
	if n, _ := det.Scan([]byte("an entirely different sentence about weather and travel plans today")); n != 0 {
		t.Fatalf("unrelated text = %d, want 0", n)
	}
}

func TestIDMTwoDocsDoNotCombine(t *testing.T) {
	// Two equal-size docs; fraction 0.5 → each needs 2 of its shingles. A mixed input
	// carries exactly ONE shingle of each. Per-doc: 1 < 2 for both → no match. If the
	// tally were global it would see 2 and falsely fire — this isolates the grouping.
	docA := "alpha bravo charlie delta echo foxtrot golf hotel"     // 8 words → 4 shingles
	docB := "november oscar papa quebec romeo sierra tango uniform" // 8 words → 4 shingles
	idx, skipped := BuildDocumentIndex([]string{docA, docB}, DefaultShingleK, 0.5)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	det := idm{index: idx}

	// "alpha bravo charlie delta echo" = 1 shingle of A; "november oscar papa quebec
	// romeo" = 1 shingle of B. The boundary produces only non-indexed shingles.
	mixed := "alpha bravo charlie delta echo zzz november oscar papa quebec romeo"
	if n, _ := det.Scan([]byte(mixed)); n != 0 {
		t.Fatalf("one shingle from each of two docs = %d, want 0 (must not combine)", n)
	}
}

func TestIDMSkipsTinyDocument(t *testing.T) {
	// A doc with only one shingle's worth of words (< 2 distinct shingles) is skipped.
	idx, skipped := BuildDocumentIndex([]string{"only five words here now", confidentialDoc}, DefaultShingleK, 0.3)
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the tiny doc)", skipped)
	}
	if idx.Size() != 1 {
		t.Fatalf("index size = %d, want 1", idx.Size())
	}
}

func TestIDMSerializeCarriesNoRawText(t *testing.T) {
	idx := docIndex(t)
	blob := idx.Marshal()
	for _, raw := range []string{"merger", "Acme", "forty two dollars", "shareholder"} {
		if bytes.Contains(bytes.ToLower(blob), []byte(strings.ToLower(raw))) {
			t.Fatalf("serialized document index leaked %q", raw)
		}
	}
	loaded, err := LoadDocumentIndex(blob)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	det := idm{index: loaded}
	excerpt := "acme acquiring all outstanding shares of beta at a price of forty two dollars per share, subject to regulatory approval and shareholder ratification and material non public information"
	if n, _ := det.Scan([]byte(excerpt)); n != 1 {
		t.Fatal("reloaded document index did not match the excerpt")
	}
	if _, err := LoadDocumentIndex([]byte("tiny")); err == nil {
		t.Error("a truncated document-index blob should fail to load")
	}
}

func TestIDMDetectorIntegration(t *testing.T) {
	c := NewWithIDM(docIndex(t))
	excerpt := "acme acquiring all outstanding shares of beta at a price of forty two dollars per share, subject to regulatory approval and shareholder ratification this agreement contains material non public information"
	hits, err := c.Classify(context.Background(), strings.NewReader(excerpt))
	if err != nil {
		t.Fatal(err)
	}
	if !hasHit(hits, corev1.DetectorType_DETECTOR_TYPE_IDM) {
		t.Fatal("expected an IDM hit for a document excerpt")
	}
	def := New()
	h2, _ := def.Classify(context.Background(), strings.NewReader(excerpt))
	if hasHit(h2, corev1.DetectorType_DETECTOR_TYPE_IDM) {
		t.Fatal("the default classifier must not report IDM")
	}
}
