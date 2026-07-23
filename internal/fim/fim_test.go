package fim

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func driftMap(drifts []Drift) map[string]Change {
	m := make(map[string]Change, len(drifts))
	for _, d := range drifts {
		m[filepath.Base(d.Path)] = d.Change
	}
	return m
}

// TestScanDetectsTimestompedModification is the KILLER test: a content change that
// PRESERVES mtime and size (the standard tamper evasion) is caught by the hash — the
// whole point of FIM over the size+mtime filewatch connector.
func TestScanDetectsTimestompedModification(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "critical.conf")
	write(t, f, "AAAA") // 4 bytes
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	origMtime := fi.ModTime()

	base, _, err := BuildBaseline([]string{f}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Change the content to the SAME length, then restore the original mtime — size and
	// mtime are now identical to the baseline; only the content (hash) differs.
	write(t, f, "BBBB")
	if err := os.Chtimes(f, origMtime, origMtime); err != nil {
		t.Fatal(err)
	}
	cur, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Size() != fi.Size() || !cur.ModTime().Equal(origMtime) {
		t.Fatalf("test setup failed to preserve size/mtime: size %d→%d, mtime eq=%v", fi.Size(), cur.Size(), cur.ModTime().Equal(origMtime))
	}

	drifts, _, err := Scan(base, []string{f}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := driftMap(drifts); got["critical.conf"] != Modified {
		t.Fatalf("timestomped modification not caught: drifts=%v (a size+mtime check would MISS this — the hash must catch it)", got)
	}
}

func TestScanDetectsDeletion(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "passwd")
	write(t, f, "root:x:0:0")
	base, _, _ := BuildBaseline([]string{f}, Options{})

	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	drifts, _, err := Scan(base, []string{f}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := driftMap(drifts); got["passwd"] != Deleted {
		t.Fatalf("deletion not detected: %v", got)
	}
}

func TestScanDetectsAddition(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a"), "one")
	base, _, _ := BuildBaseline([]string{dir}, Options{})

	write(t, filepath.Join(dir, "b"), "two") // a NEW file in the watched dir
	drifts, _, err := Scan(base, []string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := driftMap(drifts); got["b"] != Added {
		t.Fatalf("addition not detected: %v", got)
	}
}

func TestScanCleanNoDrift(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "stable")
	write(t, f, "unchanged")
	base, _, _ := BuildBaseline([]string{f}, Options{})

	drifts, _, err := Scan(base, []string{f}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 0 {
		t.Fatalf("an unchanged file produced drift (false positive): %v", drifts)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x")
	write(t, f, "content")
	base, _, _ := BuildBaseline([]string{f}, Options{})

	mfile := filepath.Join(dir, "baseline.json")
	if err := SaveManifest(mfile, base); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadManifest(mfile)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(f)
	if loaded.Entries[abs].SHA256 != base.Entries[abs].SHA256 || loaded.Entries[abs].SHA256 == "" {
		t.Fatalf("hash did not round-trip: %q vs %q", loaded.Entries[abs].SHA256, base.Entries[abs].SHA256)
	}
	// A scan against the LOADED manifest behaves identically to the original.
	write(t, f, "tampered")
	d1, _, _ := Scan(base, []string{f}, Options{})
	d2, _, _ := Scan(loaded, []string{f}, Options{})
	if len(d1) != 1 || len(d2) != 1 || d1[0].Change != d2[0].Change {
		t.Fatalf("loaded manifest scanned differently: %v vs %v", d1, d2)
	}
}

func TestOversizedFileFlaggedNotSkipped(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big")
	write(t, f, "0123456789") // 10 bytes
	base, _, err := BuildBaseline([]string{f}, Options{MaxHashBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(f)
	e, ok := base.Entries[abs]
	if !ok {
		t.Fatal("oversized file was SKIPPED — it must be recorded (flagged), never silently omitted")
	}
	if !e.Oversized {
		t.Errorf("oversized file not flagged: %+v", e)
	}
}

// A directory scan reflects mtime resolution is irrelevant (hash-based); this just
// exercises that repeated scans are stable (no spurious drift) across a small delay.
func TestRepeatedScanStable(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "f"), "x")
	base, _, _ := BuildBaseline([]string{dir}, Options{})
	time.Sleep(10 * time.Millisecond)
	drifts, _, _ := Scan(base, []string{dir}, Options{})
	if len(drifts) != 0 {
		t.Fatalf("spurious drift on a re-scan: %v", drifts)
	}
}
