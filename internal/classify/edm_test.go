package classify

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func TestEDMBloomContainsAndFP(t *testing.T) {
	idx := NewEDMIndex(0.01, 1000)
	added := make([]string, 1000)
	for i := range added {
		added[i] = fmt.Sprintf("ACCT-%08d-XZ", i)
		idx.Add(added[i])
	}
	// Every added value is contained.
	for _, v := range added {
		if !idx.Contains(v) {
			t.Fatalf("added value %q not contained", v)
		}
	}
	// Empirical FP over distinct never-added values stays near the target.
	fp, trials := 0, 20000
	for i := 0; i < trials; i++ {
		if idx.Contains(fmt.Sprintf("NOPE-%08d-QQ", i)) {
			fp++
		}
	}
	rate := float64(fp) / float64(trials)
	if rate > 0.05 { // target 0.01, allow headroom for a small index
		t.Fatalf("empirical FP %.4f too high (target ~0.01)", rate)
	}
	if idx.EstimatedFP() > 0.05 {
		t.Fatalf("estimated FP %.4f unexpectedly high", idx.EstimatedFP())
	}
}

func TestEDMNormalizationAcrossFormatting(t *testing.T) {
	idx := NewEDMIndex(0.001, 10)
	idx.Add("1234-5678-9012") // indexed with dashes
	if !idx.Contains("1234 5678 9012") {
		t.Error("value should match across formatting (spaces vs dashes)")
	}
	if !idx.Contains("123456789012") {
		t.Error("value should match with separators stripped")
	}
}

func TestBuildEDMIndexSkipsLowEntropy(t *testing.T) {
	values := []string{
		"john", "mary", "the", // low-entropy dictionary words -> skipped
		"ACCT-00099812-XZ", // distinctive identifier -> indexed
		"MEMBER-55521190",  // distinctive -> indexed
		"a1b2c3",           // 6 alnum with digits -> indexed
	}
	idx, skipped := BuildEDMIndex(values, 0.001)
	if skipped != 3 {
		t.Fatalf("skipped = %d, want 3 low-entropy tokens", skipped)
	}
	if !idx.Contains("ACCT-00099812-XZ") || !idx.Contains("MEMBER-55521190") || !idx.Contains("a1b2c3") {
		t.Error("distinctive values should be indexed")
	}
	if idx.Contains("john") || idx.Contains("mary") {
		t.Error("low-entropy words should not have been indexed")
	}
}

func TestEDMSerializeRoundTripCarriesNoRawValue(t *testing.T) {
	secret := "SUPERSECRET-ACCOUNT-42424242"
	idx := NewEDMIndex(0.001, 10)
	idx.Add(secret)

	blob := idx.Marshal()
	// The serialized index must NOT contain the raw value (nor its normalized form).
	if bytes.Contains(blob, []byte(secret)) || bytes.Contains(blob, []byte(normalizeEDM(secret))) {
		t.Fatal("serialized EDM index leaked the raw value")
	}
	loaded, err := LoadEDMIndex(blob)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Contains(secret) {
		t.Fatal("reloaded index does not match the indexed value")
	}
	if _, err := LoadEDMIndex([]byte("short")); err == nil {
		t.Error("a truncated index blob should fail to load")
	}
}

func TestEDMDetector(t *testing.T) {
	idx, _ := BuildEDMIndex([]string{"ACCT-00099812-XZ", "MEMBER-55521190"}, 0.001)
	c := NewWithEDM(idx)

	// Content carrying an indexed value (in different formatting).
	hits, err := c.Classify(context.Background(), strings.NewReader("please review acct 00099812 xz for the customer"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasHit(hits, corev1.DetectorType_DETECTOR_TYPE_EDM) {
		t.Fatal("expected an EDM hit for content carrying an indexed value")
	}

	// Content with only a distinctive NON-indexed value → no EDM hit (within FP).
	hits2, _ := c.Classify(context.Background(), strings.NewReader("ticket UNRELATED-71830011-AB is closed"))
	if hasHit(hits2, corev1.DetectorType_DETECTOR_TYPE_EDM) {
		t.Fatal("did not expect an EDM hit for a non-indexed value")
	}

	// The default classifier (no EDM) never reports EDM.
	def := New()
	hits3, _ := def.Classify(context.Background(), strings.NewReader("acct 00099812 xz"))
	if hasHit(hits3, corev1.DetectorType_DETECTOR_TYPE_EDM) {
		t.Fatal("the default classifier must not report EDM")
	}
}

func hasHit(hits []*corev1.DetectorHit, dt corev1.DetectorType) bool {
	for _, h := range hits {
		if h.GetDetectorType() == dt {
			return true
		}
	}
	return false
}
