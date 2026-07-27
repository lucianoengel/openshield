//go:build !linux

package usb

import "fmt"

// The non-Linux stub, so the tree cross-compiles (the gate builds every command for every supported
// platform, and D313 wired this authorizer into openshield-engine, which is built everywhere).
//
// IT FAILS, LOUDLY, AND IS NOT A NO-OP. `authorized_default` is a Linux kernel interface with no
// equivalent elsewhere, so on any other platform there is nothing to write. Returning nil would make the
// engine record a successful enforcement that never happened — the silent failure the whole Enforcer
// contract is written to prevent (D14). An operator on a platform where this cannot work should learn it
// from an error, not from a ledger that says a device was blocked.
type SysfsAuthorizer struct {
	// Root is accepted so the type is identical across platforms; it is unused here.
	Root string
}

func (SysfsAuthorizer) SetDefaultAuthorized(bool) error {
	return fmt.Errorf("usb: setting the USB authorization default is Linux-only (it writes the kernel's " +
		"authorized_default), so USB posture enforcement is not available on this platform")
}
