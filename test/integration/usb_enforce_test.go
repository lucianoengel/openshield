//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// USB ENFORCEMENT, end to end (T-020/D313).
//
// T-020's capability spec called the USB enforcer "the first real (non-stub) enforcer ... proving the
// Enforcer contract end to end with an actual enforcement point". Three separate things were missing from
// that sentence, and each on its own made it false:
//
//   1. NOTHING COULD OBSERVE an attachment. `DeviceSource` had only a test fake until D312.
//   2. THE POLICY COULD NOT SEE a USB event. The subject reached Rego never — a policy could not tell a
//      memory stick from a file write, so the rule an operator was told to write could not be written.
//   3. NO BINARY REGISTERED THE ENFORCER. A BLOCK decision on a USB event had nothing to carry it out.
//
// Each half had unit tests and passed them. That is the shape this suite exists to catch: three green
// packages that do not add up to a working capability.
//
// WHY THIS RUNS WITHOUT ROOT. The sysfs root is a setting, so the scenario points the producer AND the
// enforcer at a fixture tree and drives the real pipeline against it. Writing the REAL kernel file needs
// root and is proved separately by the VM scenario below — the split is deliberate: this test proves the
// PIPELINE is assembled, that one proves the WRITE lands on a real controller. Neither proves the other,
// and only running both proves the capability.

// blockOneVendorModel refuses a single vendor id and permits everything else.
//
// A rule keyed on the DEVICE MODEL, not on a person: vendor and product identify the hardware model, and
// the serial is already a keyed pseudonym when it arrives (D23). "Block this class of device" is a
// posture an operator can actually hold; "block this employee's stick" is not one this product offers.
const blockOneVendorModel = `package openshield
import rego.v1
banned if { input.event.usb.vendor_id == "0781" }
decision := {"action":"BLOCK","reason":"an unapproved USB device model was attached"} if { banned }
decision := {"action":"ALLOW","reason":"permitted device"} if { not banned }`

// fakeSysfs builds a USB tree: one controller carrying authorized_default, plus whatever devices are
// named. The controller is what the ENFORCER writes; the devices are what the PRODUCER reads.
func fakeSysfs(t *testing.T, devices map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(dir, name, val string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// usb1 is a root hub: it holds authorized_default AND has a vendor/product of its own, exactly as a
	// real tree does. Including it is not decoration — the enforcer globs `usb*` and the producer reads
	// every directory with an idVendor, so a fixture without it would be a tree neither half recognises.
	hub := filepath.Join(root, "usb1")
	write(hub, "idVendor", "1d6b")
	write(hub, "idProduct", "0002")
	write(hub, "authorized_default", "1")

	for name, vendor := range devices {
		dir := filepath.Join(root, name)
		write(dir, "idVendor", vendor)
		write(dir, "idProduct", "5567")
		write(dir, "serial", "FIXTURE-"+name)
		// An INTERFACE beside each device, which a real tree always has. The producer must skip it; if it
		// did not, one stick would arrive as several identity-less events and the vendor rule below would
		// be evaluated against an empty vendor id.
		write(filepath.Join(root, name+":1.0"), "bInterfaceNumber", "00")
	}
	return root
}

func usbPosture(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "usb1", "authorized_default"))
	if err != nil {
		t.Fatalf("reading the controller's authorization default: %v", err)
	}
	return string(b)
}

// TestAnUnapprovedUSBDeviceIsBlockedAtTheController drives the whole chain: sysfs → producer → policy →
// Decision → enforcer → the kernel's authorization byte.
func TestAnUnapprovedUSBDeviceIsBlockedAtTheController(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	policy := filepath.Join(work, "usb.rego")
	if err := os.WriteFile(policy, []byte(blockOneVendorModel), 0o600); err != nil {
		t.Fatal(err)
	}
	// 0781 is the banned vendor; 090c is not. BOTH are present, so the assertion cannot pass against an
	// enforcer that blocks on any attachment at all — which is the likelier bug and the worse one, since
	// it would deauthorise the operator's keyboard the moment the engine started.
	root := fakeSysfs(t, map[string]string{"1-4": "0781", "1-5": "090c"})

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_USB_SYSFS=" + root,
		"OPENSHIELD_USB_INTERVAL=1s",
		"OPENSHIELD_USB_ENFORCE=1",
	})
	eng.WaitForOutput("usb-posture", 90*time.Second)

	deadline := time.Now().Add(60 * time.Second)
	for usbPosture(t, root) != "0" {
		if time.Now().After(deadline) {
			t.Fatalf("a banned USB device model was attached and the controller's authorization default is "+
				"still %q. Every stage of this has its own passing unit test; what they do not prove is that "+
				"anything CONNECTS them, and until D313 nothing did — the policy never saw the device and no "+
				"binary registered the enforcer\n%s", usbPosture(t, root), eng.Output())
		}
		time.Sleep(500 * time.Millisecond)
	}

	// AND THE OPERATOR CAN GET BACK. The enforcer deliberately never clears the latch, so without this
	// command a blocked machine stays blocked — on a laptop with a USB keyboard, without the keyboard
	// needed to type the fix. ENCRYPT_LOCAL shipped in exactly that state for four rounds (D293).
	if out, err := runCapture(t, "openshield-provision", nil, "usb-authorize", "--sysfs", root); err != nil {
		t.Fatalf("clearing the USB posture latch: %v\n%s", err, out)
	}
	if got := usbPosture(t, root); got != "1" {
		t.Errorf("after usb-authorize the controller's authorization default is %q, want \"1\" — a "+
			"containment action the product can take and cannot undo is one an operator is right to "+
			"refuse to enable, and refusing to enable it is the outcome that loses", got)
	}
}

// TestAPermittedUSBDeviceLeavesTheControllerAuthorized is the half that makes the one above mean
// something. Without it, an enforcer wired to fire on every event — or on none of the policy's reasoning —
// would look identical.
func TestAPermittedUSBDeviceLeavesTheControllerAuthorized(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	policy := filepath.Join(work, "usb.rego")
	if err := os.WriteFile(policy, []byte(blockOneVendorModel), 0o600); err != nil {
		t.Fatal(err)
	}
	root := fakeSysfs(t, map[string]string{"1-5": "090c"}) // permitted vendor only

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_USB_SYSFS=" + root,
		"OPENSHIELD_USB_INTERVAL=1s",
		"OPENSHIELD_USB_ENFORCE=1",
	})
	eng.WaitForOutput("usb: device observed", 90*time.Second)
	// Long enough for several polling ticks, so "still authorized" means the enforcer decided not to
	// deauthorise rather than not having got round to it yet.
	time.Sleep(5 * time.Second)

	if got := usbPosture(t, root); got != "1" {
		t.Errorf("a PERMITTED device was attached and the controller's authorization default became %q. "+
			"The kernel switch is per-CONTROLLER, so this does not refuse one device — it refuses every "+
			"device attached afterwards, including the keyboard the operator would need to undo it\n%s",
			got, eng.Output())
	}
}

// TestTheUSBEnforcerIsNotRegisteredUnlessAskedFor.
//
// The enforcer writes a machine-wide kernel posture, so it is a SEPARATE setting from enforcement in
// general: an operator turning on file quarantine has not thereby agreed that the product may decide
// which hardware their machine accepts. This asserts the default is off — the failure it guards against
// is a deployment that starts refusing USB devices because someone enabled an unrelated feature.
func TestTheUSBEnforcerIsNotRegisteredUnlessAskedFor(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	policy := filepath.Join(work, "usb.rego")
	if err := os.WriteFile(policy, []byte(blockOneVendorModel), 0o600); err != nil {
		t.Fatal(err)
	}
	root := fakeSysfs(t, map[string]string{"1-4": "0781"}) // the BANNED vendor, and still no enforcement

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_USB_SYSFS=" + root,
		"OPENSHIELD_USB_INTERVAL=1s",
		// OPENSHIELD_USB_ENFORCE deliberately absent.
	})
	eng.WaitForOutput("usb: device observed", 90*time.Second)
	time.Sleep(5 * time.Second)

	if got := usbPosture(t, root); got != "1" {
		t.Errorf("the USB posture enforcer changed the controller's authorization default to %q without "+
			"OPENSHIELD_USB_ENFORCE being set. Changing which hardware a machine accepts is a deployment "+
			"decision an operator makes explicitly, never a side effect of enabling something else", got)
	}
	if contains(eng.Output(), "usb-posture") {
		t.Errorf("the engine announced the USB posture enforcer without being asked for it\n%s", eng.Output())
	}
}
