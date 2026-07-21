//go:build !linux

package sandbox

// Apply cannot install a seccomp filter off Linux. It returns ErrUnsupported —
// never nil — so the worker surfaces "sandbox not applied" loudly rather than
// letting an unsandboxed dev build pass for a sandboxed one. Only Linux ships
// (D9), so production always takes the linux path.
func Apply() error { return ErrUnsupported }
