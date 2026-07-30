//go:build unix

package quarantine_test

import (
	"path/filepath"
	"syscall"
	"testing"
)

// mkfifoTarget creates a FIFO to stand in for a non-regular file swapped in between classification and
// enforcement (the D65 TOCTOU). Returns "" when this platform cannot make one, so the caller simply drops
// that case rather than skipping the whole test.
func mkfifoTarget(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "afifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Logf("skipping the fifo case: %v", err)
		return ""
	}
	return p
}
