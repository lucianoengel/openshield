// Package canary is the ransomware canary engine (HIPS-4): it plants decoy files and detects the
// ransomware signature — a CORRELATED mass change of those decoys within a short window.
//
// Ransomware's defining behavior is walking a tree and encrypting everything; FIM (internal/fim)
// detects tampering of SPECIFIC critical files, but ransomware's louder signal is MANY files changing
// at once. Canaries exploit that: innocuous decoys no legitimate process should touch, so when several
// of them change (are encrypted or deleted) within the window, that correlated mass-change is a
// high-confidence ransomware detection — caught while the encryption is still spreading.
package canary

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Plant writes n decoy files into dir (creating dir if needed) and returns their paths. It is
// idempotent: an existing canary is NOT overwritten, so its known-good baseline stays stable across
// restarts. The names/content are plausible-but-recognizable so ransomware treats them as ordinary
// targets while the agent can identify them.
func Plant(dir string, n int) ([]string, error) {
	if n <= 0 {
		return nil, fmt.Errorf("canary: count must be positive")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for i := 0; i < n; i++ {
		// Plausible document-like names so ransomware encrypts them like real files.
		name := fmt.Sprintf(".~archive_%04d.docx", i)
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p) // already planted — keep its baseline
			continue
		}
		content := fmt.Sprintf("OpenShield canary %d — do not modify. This is a decoy file used to "+
			"detect ransomware; a legitimate process has no reason to touch it.\n", i)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// Entropy returns the Shannon entropy of b in bits per byte (0..8). Near-maximal entropy (≈8) is the
// signature of encrypted (or compressed) content — a canary rewritten to high entropy was encrypted.
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Detector fires when a THRESHOLD of DISTINCT canaries change within a trailing WINDOW — the ransomware
// mass-change signature, distinct from a lone canary edit. It is concurrency-safe.
type Detector struct {
	Threshold int
	Window    time.Duration

	mu      sync.Mutex
	changed map[string]time.Time // canary path → most recent change within the window
}

// Observe records that a canary changed at time `at` and returns true when the number of distinct
// canaries changed within [at-Window, at] reaches Threshold. Entries older than the window are pruned,
// so slow background churn never accumulates to a false detection; a single canary flapping counts once.
func (d *Detector) Observe(canaryPath string, at time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = map[string]time.Time{}
	}
	d.changed[canaryPath] = at
	cutoff := at.Add(-d.Window)
	count := 0
	for p, t := range d.changed {
		if t.Before(cutoff) {
			delete(d.changed, p)
			continue
		}
		count++
	}
	return count >= d.Threshold
}

// Reset clears the window (e.g. after a detection has been reported, to avoid re-firing every event).
func (d *Detector) Reset() {
	d.mu.Lock()
	d.changed = nil
	d.mu.Unlock()
}
