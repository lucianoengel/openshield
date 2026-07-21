//go:build linux

package sandbox

import (
	"fmt"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

// Apply installs the seccomp network-deny filter on the current process.
//
// It must be called BEFORE the worker reads any attacker-controlled input: a
// filter applied after the first byte is read races a fast exploit. It loads
// with NO_NEW_PRIVS (so it needs no privilege) and TSYNC (so it covers every Go
// runtime thread, not only the caller — a thread-local filter would be trivially
// bypassable from another goroutine).
func Apply() error {
	if !seccomp.Supported() {
		return ErrUnsupported
	}
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{{
				Action: seccomp.ActionErrno,
				Names:  deniedSyscalls,
			}},
		},
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		return fmt.Errorf("sandbox: loading seccomp filter: %w", err)
	}
	return nil
}
