package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	usbenf "github.com/lucianoengel/openshield/internal/enforcers/usb"
)

// CLEARING THE USB POSTURE LATCH (D313).
//
// The USB enforcer sets `authorized_default` to 0 on every controller when a policy BLOCKs an attachment,
// and it deliberately does NOT set it back: the kernel switch is machine-wide while decisions are per
// device, so an enforcer that also enacted ALLOW would release the block on the next permitted keyboard.
//
// That makes clearing it an OPERATOR action, and an operator action needs a command. Without one this
// enforcer would be the ENCRYPT_LOCAL mistake again (D293): a containment action the product can take and
// cannot undo, leaving a machine that refuses every USB device it is offered — including, on a laptop with
// a USB keyboard, the one needed to type the fix. That is a security control an operator is right to
// refuse to enable, and refusing to enable it is the outcome that loses.
//
// IT LIVES IN openshield-provision, not in the engine, because it is an AUTHORITY operation performed
// locally by a human with root (D51's issuance shape): a network route that re-authorises USB would be a
// remote control for switching the device policy off, reachable by whatever can reach the control plane.
//
// It reports what it changed, per controller, because "it worked" is not a useful answer when the reason
// you are running it is that a machine is not behaving as expected.

func usbAuthorize(f map[string][]string) int {
	root := one(f, "sysfs")
	restrict := has(f, "block")

	before, err := readPostures(root)
	if err != nil {
		return fail("%v", err)
	}
	if len(before) == 0 {
		return fail("no USB controllers found under %s — either this machine has none, or --sysfs points "+
			"somewhere that is not a sysfs USB tree", sysfsRootOr(root))
	}
	if err := (usbenf.SysfsAuthorizer{Root: root}).SetDefaultAuthorized(!restrict); err != nil {
		// Named plainly: the overwhelmingly likely cause is running it without root, and "permission
		// denied" on a path the operator did not name is a confusing way to learn that.
		return fail("setting the USB authorization default: %v\n(writing authorized_default needs root; "+
			"this is the same privilege the enforcer needs to set it in the first place)", err)
	}
	after, err := readPostures(root)
	if err != nil {
		return fail("%v", err)
	}

	want := "1"
	if restrict {
		want = "0"
	}
	for _, c := range sortedKeys(after) {
		fmt.Fprintf(os.Stderr, "openshield-provision: %s authorized_default %s → %s\n", c, before[c], after[c])
		if after[c] != want {
			return fail("%s is %q after the write, want %q — the write reported success and the kernel "+
				"did not take it, so do not trust this machine's USB posture", c, after[c], want)
		}
	}
	if restrict {
		fmt.Fprintln(os.Stderr, "openshield-provision: NEW devices attached from now on are DEAUTHORISED. "+
			"Devices already attached keep working — this is not a disconnect.")
	} else {
		fmt.Fprintln(os.Stderr, "openshield-provision: newly attached devices are permitted again. If the "+
			"policy that blocked one is still in force, the next matching attachment re-latches this.")
	}
	return 0
}

// readPostures reports each controller's current authorized_default, so the change is shown rather than
// asserted.
func readPostures(root string) (map[string]string, error) {
	matches, err := filepath.Glob(filepath.Join(sysfsRootOr(root), "usb*", "authorized_default"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		out[filepath.Base(filepath.Dir(p))] = strings.TrimSpace(string(b))
	}
	return out, nil
}

func sysfsRootOr(root string) string {
	if root == "" {
		return "/sys/bus/usb/devices"
	}
	return root
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
