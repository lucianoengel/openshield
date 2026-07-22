package classify

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// records: name + a distinctive account id + a distinctive member id.
func sampleRecords() [][]string {
	return [][]string{
		{"Alice Johnson", "ACCT-00099812-XZ", "MEMBER-55521190"},
		{"Bob Smith", "ACCT-71830011-AB", "MEMBER-44409922"},
	}
}

func TestRecordEDMRequiresMultipleCells(t *testing.T) {
	idx, skipped := BuildRecordIndex(sampleRecords(), 2)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0 (each record has ≥2 distinctive cells)", skipped)
	}
	det := edmRecord{index: idx}

	// TWO cells of Alice's record co-occur (across formatting) → a match.
	twoCells := "invoice for acct 00099812 xz linked to member 55521190 please review"
	if n, _ := det.Scan([]byte(twoCells)); n != 1 {
		t.Fatalf("two cells of one record = %d matches, want 1", n)
	}

	// ONE cell of a record → NO match (the multi-cell precision).
	oneCell := "just the account acct 00099812 xz appears here"
	if n, _ := det.Scan([]byte(oneCell)); n != 0 {
		t.Fatalf("one cell of a record = %d matches, want 0", n)
	}

	// One cell each from TWO different records → NO match (cells don't combine).
	crossRecord := "acct 00099812 xz and unrelated member 44409922 in one note"
	if n, _ := det.Scan([]byte(crossRecord)); n != 0 {
		t.Fatalf("one cell each from two records = %d matches, want 0", n)
	}
}

func TestRecordEDMSkipsTooSmallRecords(t *testing.T) {
	// A record with only ONE distinctive cell (the name is skipped as low-entropy,
	// leaving one id) cannot reach threshold 2 → skipped.
	records := [][]string{
		{"Carol Lee", "ACCT-90001112-QQ"}, // one distinctive cell after name-skip
		{"Dan Roe", "ACCT-33322211-RR", "MEMBER-88877766"},
	}
	idx, skipped := BuildRecordIndex(records, 2)
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the single-distinctive-cell record)", skipped)
	}
	// The skipped record's cell must never match.
	det := edmRecord{index: idx}
	if n, _ := det.Scan([]byte("acct 90001112 qq")); n != 0 {
		t.Fatalf("a skipped record's lone cell matched (%d)", n)
	}
	// The kept record still matches on two cells.
	if n, _ := det.Scan([]byte("acct 33322211 rr member 88877766")); n != 1 {
		t.Fatalf("the kept record did not match (%d)", n)
	}
}

func TestRecordEDMSerializeCarriesNoRawValue(t *testing.T) {
	idx, _ := BuildRecordIndex(sampleRecords(), 2)
	blob := idx.Marshal()
	for _, raw := range []string{"ACCT-00099812-XZ", "acct00099812xz", "MEMBER-55521190", "Alice"} {
		if bytes.Contains(blob, []byte(raw)) {
			t.Fatalf("serialized record index leaked %q", raw)
		}
	}
	loaded, err := LoadRecordIndex(blob)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	det := edmRecord{index: loaded}
	if n, _ := det.Scan([]byte("acct 00099812 xz member 55521190")); n != 1 {
		t.Fatal("reloaded record index did not match")
	}
	if _, err := LoadRecordIndex([]byte("tiny")); err == nil {
		t.Error("a truncated record-index blob should fail to load")
	}
}

func TestRecordEDMDetectorIntegration(t *testing.T) {
	idx, _ := BuildRecordIndex(sampleRecords(), 2)
	c := NewWithRecordEDM(idx)
	hits, err := c.Classify(context.Background(), strings.NewReader("acct 00099812 xz for member 55521190"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasHit(hits, corev1.DetectorType_DETECTOR_TYPE_EDM) {
		t.Fatal("expected an EDM hit for a multi-cell record match")
	}
	// Default classifier reports no EDM.
	def := New()
	h2, _ := def.Classify(context.Background(), strings.NewReader("acct 00099812 xz member 55521190"))
	if hasHit(h2, corev1.DetectorType_DETECTOR_TYPE_EDM) {
		t.Fatal("the default classifier must not report EDM")
	}
}
