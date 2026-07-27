//go:build linux

package usb_test

import (
	"os"
	"path/filepath"
	"strings"
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

// THE REAL KERNEL (D313). Root-gated, and it exists because the fixture test above cannot fail for the
// reason that matters: a temp directory accepts any bytes, and `/sys` does not.
//
// TWO THINGS ONLY A REAL KERNEL CAN PROVE, and both are invisible to the fixture test because that test
// supplies its own Root and its own file names:
//
//  1. THE HARDCODED PATH AND GLOB ARE RIGHT. `/sys/bus/usb/devices` + `usb*/authorized_default` are the
//     product's own claim about where the kernel keeps this switch, and every test that passes a Root
//     substitutes its own answer for that claim. Get it wrong and the enforcer finds no controllers on
//     every real machine — while every fixture test stays green.
//  2. SYSFS FILES ARE NOT FILES. They are attribute handlers that reject what they dislike (a wrong
//     width, a value out of range) with EINVAL on WRITE. A temp file accepts any bytes.
//
// The value is READ BACK from the controller, so an accepted write is distinguished from a merely
// well-formed one.
//
// It RESTORES the posture with t.Cleanup, and the ordering matters: leaving a test machine refusing every
// newly attached USB device is exactly the outage this enforcer's honest limit warns about, and a test
// that inflicts it is a bad citizen on the machine it runs on.
func TestSysfsAuthorizerAgainstTheRealKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("writing a real USB controller's authorized_default needs root — run this on the rooted VM")
	}
	const realRoot = "/sys/bus/usb/devices"
	controllers, err := filepath.Glob(filepath.Join(realRoot, "usb*", "authorized_default"))
	if err != nil {
		t.Fatal(err)
	}
	if len(controllers) == 0 {
		t.Skip("this machine exposes no USB controllers, so there is nothing to write")
	}

	read := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, p := range controllers {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("reading %s: %v", p, err)
			}
			out[p] = strings.TrimSpace(string(b))
		}
		return out
	}

	original := read()
	a := usbenf.SysfsAuthorizer{}
	// Registered BEFORE the first write, so a failure part-way through still restores.
	t.Cleanup(func() {
		for p, v := range original {
			if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
				t.Errorf("RESTORING %s to %q failed: %v — this machine may now refuse newly attached "+
					"USB devices; clear it with `openshield-provision usb-authorize`", p, v, err)
			}
		}
	})

	if err := a.SetDefaultAuthorized(false); err != nil {
		t.Fatalf("the kernel refused the deauthorising write: %v", err)
	}
	for p, v := range read() {
		if v != "0" {
			t.Errorf("%s = %q after BLOCK, want 0. The write returned no error and the kernel did not "+
				"take the value, which is the failure mode a fixture tree can never reproduce: a temp "+
				"file accepts any bytes, a sysfs attribute handler validates them", p, v)
		}
	}

	if err := a.SetDefaultAuthorized(true); err != nil {
		t.Fatalf("the kernel refused the re-authorising write: %v — the posture is now latched shut "+
			"with no way back, which is precisely what `openshield-provision usb-authorize` exists to "+
			"prevent", err)
	}
	for p, v := range read() {
		if v != "1" {
			t.Errorf("%s = %q after clearing, want 1", p, v)
		}
	}
}
