//go:build !unix

package safeio

import (
	"fmt"
	"os"
)

// ReadRegularNoFollow is the non-unix fallback. The OpenShield endpoint is Linux;
// on other platforms this is best-effort: lstat-reject a symlink, require a
// regular file, then read. It carries a small lstat→open TOCTOU the unix path
// (O_NOFOLLOW) does not — acceptable because these platforms are not endpoint
// targets (D65).
func ReadRegularNoFollow(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("safeio: lstat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("safeio: %s is a symlink — refusing", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("safeio: %s is not a regular file (mode %s) — refusing", path, fi.Mode())
	}
	return os.ReadFile(path)
}
