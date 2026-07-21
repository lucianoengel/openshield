//go:build unix

package safeio

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// ReadRegularNoFollow reads path WITHOUT following a final-component symlink and
// only if it is a REGULAR file, closing the classification→enforcement TOCTOU
// where an attacker swaps the flagged path for a symlink (or a special file) to
// redirect an enforcer's read onto an arbitrary file (D65).
//
// O_NOFOLLOW makes the open fail (ELOOP) if the final component is a symlink;
// fstat on the returned fd rejects a directory/fifo/device/socket. It operates on
// the fd, not by re-resolving the path.
//
// Residual (documented): O_NOFOLLOW guards only the FINAL component; a
// parent-directory-component swap needs openat2 RESOLVE_NO_SYMLINKS, and the
// strongest fix carries an fd from classification through enforcement.
func ReadRegularNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("safeio: opening %s (refusing to follow a symlink): %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("safeio: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("safeio: %s is not a regular file (mode %s) — refusing", path, fi.Mode())
	}
	return io.ReadAll(f)
}
