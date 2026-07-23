//go:build !linux

package watchdog

import "fmt"

// FanotifyResponder is a stub off Linux so the tree cross-compiles (D9); the fanotify
// kernel edge exists only on Linux. Allow/Deny error rather than pretend to answer — a
// non-Linux build must never look like it enforced.
type FanotifyResponder struct {
	NotifyFD int
}

func (FanotifyResponder) Allow(PermissionEvent) error {
	return fmt.Errorf("watchdog: fanotify is Linux-only")
}
func (FanotifyResponder) Deny(PermissionEvent) error {
	return fmt.Errorf("watchdog: fanotify is Linux-only")
}

var _ Responder = FanotifyResponder{}
