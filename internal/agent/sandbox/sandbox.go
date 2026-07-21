// Package sandbox hardens the unprivileged parser worker in depth.
//
// The privilege split (D13/D29) already keeps attacker-controlled bytes out of
// the privileged process. This package hardens the half that DOES parse them:
// it self-applies a seccomp filter denying the network syscalls, so that a
// parser RCE — the threat the split exists for, cf. ClamAV CVE-2025-20260 —
// cannot phone home, exfiltrate over the network, or open a reverse shell. The
// capability is removed, not discouraged.
//
// What this package can enforce, it enforces in code (seccomp, decompression
// bomb limits). What belongs to the supervisor (cgroup memory/CPU limits) is
// specified for the supervisor, not faked in Go — a process cannot reliably
// self-limit its cgroup without privilege, and pretending to would be theatre.
package sandbox

import "errors"

// ErrUnsupported is returned by Apply on a platform without seccomp support. It
// is deliberately NOT nil: only Linux ships (D9), but a developer on another
// platform must see that the sandbox was not applied rather than mistake an
// unsandboxed run for a sandboxed one.
var ErrUnsupported = errors.New("sandbox: seccomp not supported on this platform")

// deniedSyscalls is the network family plus a few other primitives a
// file-scanning parser has no business calling. This is a DENYLIST, not an
// allowlist: an allowlist is stronger but breaks whenever the Go runtime starts
// using a new syscall, turning a runtime upgrade into a worker crash. The
// denylist delivers the property that matters now — no network egress — without
// that fragility. The intended end state is an allowlist (see docs/decisions.md).
var deniedSyscalls = []string{
	"socket", "socketpair", "connect", "bind", "listen",
	"accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg",
	"ptrace", "process_vm_readv", "process_vm_writev",
}
