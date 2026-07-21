// Package safeio gives the file enforcers symlink-safe file access, closing the
// classification→enforcement TOCTOU where an attacker swaps the flagged path for
// a symlink (or a special file) to redirect enforcement onto an arbitrary file
// (D65). ReadRegularNoFollow is platform-specific (O_NOFOLLOW on unix); this file
// holds the portable stat-based refusal.
package safeio

import (
	"fmt"
	"os"
)

// RefuseNonRegular returns an error if path is a symlink or is not a regular file
// (checked with lstat, so a final-component symlink is not followed). Enforcers
// call it BEFORE acting, to refuse a swapped-symlink / special-file target loudly
// rather than acting on the wrong thing.
func RefuseNonRegular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("safeio: lstat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("safeio: %s is a symlink — refusing to act on it (D65)", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("safeio: %s is not a regular file (mode %s) — refusing", path, fi.Mode())
	}
	return nil
}
