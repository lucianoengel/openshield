//go:build linux || darwin

package process

import "syscall"

// platformKill sends SIGKILL to a process. On Unix this is syscall.Kill; the safety checks
// (pid ≤ 1, self) are applied by the caller before this runs.
func platformKill(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
