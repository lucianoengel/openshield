//go:build linux

package usb

import (
	"fmt"
	"os"
	"path/filepath"
)

// SysfsAuthorizer writes the real kernel USB authorization default. It sets
// authorized_default on every USB controller under /sys/bus/usb/devices.
//
// This needs privilege (writing sysfs) and is deliberately tiny — every decision
// that matters lives in Enforcer, tested without privilege; this only writes the
// byte the enforcer decided.
type SysfsAuthorizer struct {
	// Root allows tests to point at a fake sysfs tree; empty means the real one.
	Root string
}

func (s SysfsAuthorizer) SetDefaultAuthorized(authorized bool) error {
	root := s.Root
	if root == "" {
		root = "/sys/bus/usb/devices"
	}
	val := []byte("0")
	if authorized {
		val = []byte("1")
	}
	matches, err := filepath.Glob(filepath.Join(root, "usb*", "authorized_default"))
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("usb: no authorized_default under %s (no USB controllers?)", root)
	}
	for _, p := range matches {
		if err := os.WriteFile(p, val, 0o644); err != nil {
			return fmt.Errorf("usb: writing %s: %w", p, err)
		}
	}
	return nil
}
