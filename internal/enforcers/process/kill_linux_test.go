//go:build linux

package process

import (
	"os"
	"path/filepath"
	"testing"
)

// Sanity that the REAL trusted-identity source works: procIdentityOf reads this test process's own
// executable via /proc/self/exe. Ownership is not asserted (CI runs non-root) — only that the real
// readlink+stat path resolves the actual binary, so the injected-seam tests exercise the same shape.
func TestProcIdentityOfReadsRealExe(t *testing.T) {
	id, err := procIdentityOf(os.Getpid())
	if err != nil {
		t.Fatalf("procIdentityOf(self): %v", err)
	}
	if id.ExePath == "" {
		t.Fatal("procIdentityOf returned an empty exe path for the running process")
	}
	if exe, err := os.Executable(); err == nil && filepath.Base(id.ExePath) != filepath.Base(exe) {
		t.Errorf("exe basename = %q, want %q (from os.Executable)", filepath.Base(id.ExePath), filepath.Base(exe))
	}
}
