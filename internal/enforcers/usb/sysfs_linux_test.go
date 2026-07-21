//go:build linux

package usb_test

import (
	"os"
	"path/filepath"
	"testing"

	usbenf "github.com/lucianoengel/openshield/internal/enforcers/usb"
)

// Exercises the REAL sysfs write against a FAKE sysfs tree — no privilege needed,
// because we point Root at a temp dir shaped like /sys/bus/usb/devices. This
// proves the authorizer writes the right byte to the right file; writing the
// actual kernel tree is a few bytes and needs root, covered by the manual note.
func TestSysfsAuthorizerWritesAuthorizedDefault(t *testing.T) {
	root := t.TempDir()
	// Two fake controllers.
	for _, ctrl := range []string{"usb1", "usb2"} {
		dir := filepath.Join(root, ctrl)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "authorized_default"), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a := usbenf.SysfsAuthorizer{Root: root}

	if err := a.SetDefaultAuthorized(false); err != nil {
		t.Fatal(err)
	}
	for _, ctrl := range []string{"usb1", "usb2"} {
		b, err := os.ReadFile(filepath.Join(root, ctrl, "authorized_default"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "0" {
			t.Errorf("%s authorized_default = %q after BLOCK, want 0", ctrl, b)
		}
	}
	if err := a.SetDefaultAuthorized(true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "usb1", "authorized_default"))
	if string(b) != "1" {
		t.Errorf("authorized_default = %q after ALLOW, want 1", b)
	}

	// No controllers → a loud error, not a silent success (an enforcement that
	// wrote nothing must not look like it succeeded).
	empty := usbenf.SysfsAuthorizer{Root: t.TempDir()}
	if err := empty.SetDefaultAuthorized(false); err == nil {
		t.Error("writing with no USB controllers present returned no error — a no-op enforcement " +
			"must surface, not pass silently")
	}
}
