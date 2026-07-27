package usb

import (
	"os"
	"path/filepath"
	"strings"
)

// SYSFS IS THE PRODUCTION DEVICE SOURCE (D312).
//
// Until now `DeviceSource` had only a test fake, so the producer could not read a real device and the
// USB capability could not observe anything — while `openspec/specs/usb-enforcement` described "the
// first real (non-stub) enforcer ... proving the Enforcer contract end to end with an actual enforcement
// point". The enforcer half was real; the eyes were not.
//
// It reads /sys/bus/usb/devices, which the kernel maintains and which needs NO privilege to read — the
// same reason the observe path uses unprivileged fanotify (D52). Enforcement needs root
// (authorized_default); OBSERVING does not, and building the producer to require it would have made a
// read-only capability privileged for no reason.

// SysfsSource enumerates attached USB devices from sysfs.
//
// Root defaults to the kernel's path; a test points it at a fixture tree. That is the only reason it is
// a field — the production caller never sets it.
type SysfsSource struct {
	Root string
}

// sysfsRoot is where the kernel exposes USB devices.
const sysfsRoot = "/sys/bus/usb/devices"

// Devices returns every attached device that carries a vendor AND product id.
//
// ENTRIES WITHOUT `idVendor` ARE SKIPPED, and that is the whole filtering rule: /sys/bus/usb/devices
// contains both DEVICES (`1-4`) and INTERFACES (`1-4:1.0`), and only devices carry the identity
// attributes. Treating an interface as a device would emit several events for one physical stick, each
// with an empty identity — noise that looks like activity.
//
// A device with NO serial is still reported. A missing serial is extremely common (hubs, many cheap
// devices) and dropping those would silently blind the connector to a whole class of hardware; the
// pseudonymiser maps an empty serial to an empty pseudonym, so the event is honest about what is known.
func (s SysfsSource) Devices() ([]Device, error) {
	root := s.Root
	if root == "" {
		root = sysfsRoot
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		// A host with no USB subsystem exposed is not an error condition — it is a host with no USB.
		// Reporting it as a failure would make an ordinary VM look broken.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Device
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		vendor := readAttr(dir, "idVendor")
		product := readAttr(dir, "idProduct")
		if vendor == "" || product == "" {
			continue // an interface, or something without an identity
		}
		out = append(out, Device{
			VendorID:  vendor,
			ProductID: product,
			Serial:    readAttr(dir, "serial"),
		})
	}
	return out, nil
}

// readAttr reads one sysfs attribute, trimming the trailing newline the kernel adds. An unreadable
// attribute is empty rather than an error: a device that hides one attribute should still be reported
// with the rest.
func readAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
