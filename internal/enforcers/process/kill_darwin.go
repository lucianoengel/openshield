//go:build darwin

package process

import (
	"fmt"
	"syscall"
)

// platformKill on macOS uses syscall.Kill; pidfd is Linux-only, so the pid-reuse-safe path (HIPS-7)
// is Linux-first (D8). macOS support exists for the CI matrix, not as a shipped enforcer.
func platformKill(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

// procComm is unsupported on macOS (no /proc) — the critical-process guard is Linux-first (D8).
func procComm(int) (string, error) { return "", fmt.Errorf("process: comm lookup unsupported on this platform") }
