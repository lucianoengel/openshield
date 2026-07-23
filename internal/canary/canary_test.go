package canary

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDetectorFiresOnThreshold: a threshold of DISTINCT canaries within the window fires; a single
// change does not; the same canary repeated does not (distinct count); changes older than the window
// are pruned.
//
// Mutation A (count total changes, not distinct): the same-canary-repeated case FAILs (false fire).
// Mutation B (no prune): the spread-out case FAILs (accumulates).
func TestDetectorFiresOnThreshold(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	d := &Detector{Threshold: 3, Window: time.Minute}

	// One change → no fire.
	if d.Observe("/c/a", base) {
		t.Fatal("a single canary change fired the detector")
	}
	// The SAME canary repeated → still 1 distinct → no fire.
	if d.Observe("/c/a", base.Add(time.Second)) || d.Observe("/c/a", base.Add(2*time.Second)) {
		t.Fatal("repeated changes to ONE canary fired — must count DISTINCT canaries")
	}
	// Two more distinct canaries → 3 distinct within the window → fire.
	if !d.Observe("/c/b", base.Add(3*time.Second)) {
		// only 2 distinct so far (a,b) → should NOT fire yet
	}
	if got := d.Observe("/c/c", base.Add(4*time.Second)); !got {
		t.Fatal("3 distinct canaries within the window did NOT fire")
	}

	// Spread-out: fresh detector, changes 40s apart with a 1-minute window but pruning as time advances.
	d2 := &Detector{Threshold: 3, Window: time.Minute}
	d2.Observe("/c/x", base)
	d2.Observe("/c/y", base.Add(40*time.Second))
	// By now (base+90s) the first change (base) is outside the 60s window → pruned; only y in window.
	if d2.Observe("/c/z", base.Add(90*time.Second)) {
		t.Fatal("changes spread beyond the window accumulated to a false detection (pruning broken)")
	}
}

func TestEntropy(t *testing.T) {
	// Random bytes → near 8.
	rnd := make([]byte, 4096)
	rand.Read(rnd)
	if e := Entropy(rnd); e < 7.5 {
		t.Errorf("random-bytes entropy = %.2f, want ~8 (encrypted signature)", e)
	}
	// A single repeated byte → 0.
	zeros := make([]byte, 4096)
	if e := Entropy(zeros); e != 0 {
		t.Errorf("constant-byte entropy = %.2f, want 0", e)
	}
	// Plain text → mid-range, well below 8.
	text := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 100))
	if e := Entropy(text); e < 3 || e > 5 {
		t.Errorf("text entropy = %.2f, want mid-range (3..5)", e)
	}
	if Entropy(nil) != 0 {
		t.Error("empty entropy should be 0")
	}
}

func TestPlantIdempotent(t *testing.T) {
	dir := t.TempDir()
	paths, err := Plant(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatalf("planted %d, want 5", len(paths))
	}
	// Modify one canary, then re-plant: the existing (modified) file must NOT be overwritten.
	if err := os.WriteFile(paths[0], []byte("MODIFIED"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths2, err := Plant(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths2) != 5 {
		t.Fatalf("re-plant returned %d, want 5", len(paths2))
	}
	got, _ := os.ReadFile(paths[0])
	if string(got) != "MODIFIED" {
		t.Fatal("re-plant OVERWROTE an existing canary — plant must be idempotent (stable baseline)")
	}
	// All planted files exist in the dir.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 5 {
		t.Errorf("dir has %d files, want 5", len(ents))
	}
	_ = filepath.Base(paths[0])
}
