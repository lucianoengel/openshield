// Package fim is the File Integrity Monitoring engine (HIPS-4): it detects
// TAMPERING of operator-designated critical files by comparing them against a
// persistent, known-good SHA-256 baseline.
//
// It is DISTINCT from the filewatch connector, which snapshots by size+mtime and
// ignores deletions: FIM keys on a CONTENT hash, so a modification that preserves
// mtime and size (timestomping / `touch -r`, the standard tamper evasion) is still
// caught; it detects DELETION of a baseline file (a top tamper signal); and its
// baseline is PERSISTENT, so it answers "has this drifted from its approved
// known-good state" across restarts, not merely "changed since I started watching".
//
// Hashing reads files with the caller's own credentials — no privilege, no kernel
// hooks (real-time inotify/fanotify watch is a deferred, privileged optimization).
package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// DefaultMaxHashBytes bounds how much of a file is hashed, so a huge file cannot
// stall a scan. A file larger than this is FLAGGED (Oversized), never silently
// omitted — a silent skip would read as "verified, unchanged".
const DefaultMaxHashBytes = 64 << 20 // 64 MiB

// DefaultMaxPaths bounds how many files a scan tracks; the overflow count is
// returned so the caller can surface it (silent truncation would misrepresent
// coverage).
const DefaultMaxPaths = 100_000

// Change is the kind of drift a scan found for one path.
type Change string

const (
	Modified Change = "modified" // content hash differs from the baseline
	Added    Change = "added"    // present now, not in the baseline
	Deleted  Change = "deleted"  // in the baseline, missing now
)

// Entry is the baseline record for one file: its content hash and size. Oversized
// marks a file past the hash cap — its hash covers only the first MaxHashBytes, so a
// change beyond the cap is not detected; the flag makes that explicit.
type Entry struct {
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Oversized bool   `json:"oversized,omitempty"`
}

// Manifest is the persistent known-good baseline: a map from absolute path to Entry.
type Manifest struct {
	Entries map[string]Entry `json:"entries"`
}

// Drift is one detected change from the baseline.
type Drift struct {
	Path   string
	Change Change
}

// Options tune a build/scan. Zero values fall back to the package defaults.
type Options struct {
	MaxHashBytes int64
	MaxPaths     int
}

func (o Options) maxHashBytes() int64 {
	if o.MaxHashBytes > 0 {
		return o.MaxHashBytes
	}
	return DefaultMaxHashBytes
}

func (o Options) maxPaths() int {
	if o.MaxPaths > 0 {
		return o.MaxPaths
	}
	return DefaultMaxPaths
}

// BuildBaseline hashes the critical set into a Manifest. Each path is expanded to the
// files it covers (a regular file → itself; a directory → its non-recursive regular
// files, matching the filewatch connector's scope), each hashed under the size cap.
// overflow is the number of files past MaxPaths that were NOT recorded, so the caller
// can surface incomplete coverage rather than trust a truncated baseline.
func BuildBaseline(paths []string, opts Options) (m *Manifest, overflow int, err error) {
	m = &Manifest{Entries: map[string]Entry{}}
	files, err := expand(paths)
	if err != nil {
		return nil, 0, err
	}
	for _, f := range files {
		if len(m.Entries) >= opts.maxPaths() {
			overflow++
			continue
		}
		e, err := hashFile(f, opts.maxHashBytes())
		if err != nil {
			return nil, 0, fmt.Errorf("fim: hashing %s: %w", f, err)
		}
		m.Entries[f] = e
	}
	return m, overflow, nil
}

// Scan compares the current on-disk state of the manifest's paths (plus any new files
// in the watched directories) against the baseline and returns one Drift per change,
// sorted by path for determinism. paths is the same watched set the baseline was built
// from, so a NEW file in a watched directory is detected as Added.
func Scan(m *Manifest, paths []string, opts Options) (drifts []Drift, overflow int, err error) {
	cur, overflow, err := BuildBaseline(paths, opts) // "current" is a fresh baseline of the live files
	if err != nil {
		return nil, 0, err
	}
	// modified / added: walk current, compare to baseline.
	for p, ce := range cur.Entries {
		be, ok := m.Entries[p]
		switch {
		case !ok:
			drifts = append(drifts, Drift{Path: p, Change: Added})
		case ce.SHA256 != be.SHA256:
			drifts = append(drifts, Drift{Path: p, Change: Modified})
		}
	}
	// deleted: a baseline path with no current entry.
	for p := range m.Entries {
		if _, ok := cur.Entries[p]; !ok {
			drifts = append(drifts, Drift{Path: p, Change: Deleted})
		}
	}
	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].Path != drifts[j].Path {
			return drifts[i].Path < drifts[j].Path
		}
		return drifts[i].Change < drifts[j].Change
	})
	return drifts, overflow, nil
}

// expand resolves the watched paths to the concrete regular files to hash: a regular
// file resolves to itself; a directory to its non-recursive regular files. A missing
// path is skipped (a deleted baseline path is handled by the scan's delete pass, not
// here). Results are absolute and de-duplicated.
func expand(paths []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue // missing now; the delete pass handles a baselined-but-gone path
		}
		if info.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				fi, err := e.Info()
				if err != nil || !fi.Mode().IsRegular() {
					continue
				}
				add(filepath.Join(p, e.Name()))
			}
			continue
		}
		if info.Mode().IsRegular() {
			add(p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// hashFile computes a file's SHA-256 over at most max bytes. A file larger than max is
// hashed up to the cap and flagged Oversized (never silently skipped). Size is the
// true on-disk size (for reporting), independent of the hashed prefix.
func hashFile(path string, max int64) (Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, max))
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		Size:      info.Size(),
		Oversized: n >= max && info.Size() > max,
	}, nil
}

// SaveManifest writes the manifest as JSON (0600 — the baseline is security-relevant).
func SaveManifest(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadManifest reads a JSON manifest from disk.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("fim: parsing manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return &m, nil
}

// Size reports the number of baselined files.
func (m *Manifest) Size() int {
	if m == nil {
		return 0
	}
	return len(m.Entries)
}
