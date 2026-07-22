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
	// The running test process is not root-owned under CI, so the guard sees a non-privileged binary.
	if id.RootOwned && os.Geteuid() != 0 {
		t.Errorf("RootOwned=true for a process whose binary is not root-owned (euid=%d)", os.Geteuid())
	}
}

// procIdentityOf must ERROR (not return a zero identity that could be misread as "known") for a pid
// with no /proc entry — the critical-process guard depends on a read failure meaning "gone/unreadable"
// (R34-13). A pid of 0 has no /proc/0/exe.
func TestProcIdentityOfNonexistentPidErrors(t *testing.T) {
	if _, err := procIdentityOf(0); err == nil {
		t.Fatal("procIdentityOf(0) returned no error — an unreadable process must fail, not resolve")
	}
}
