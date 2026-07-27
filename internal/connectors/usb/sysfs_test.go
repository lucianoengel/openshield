package usb_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/usb"
)

// fixture builds a sysfs-shaped tree: real devices, an interface, and a device with no serial.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(dir string, attrs map[string]string) {
		p := filepath.Join(root, dir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		for k, v := range attrs {
			if err := os.WriteFile(filepath.Join(p, k), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("1-4", map[string]string{"idVendor": "0bda", "idProduct": "5411", "serial": "ABC123"})
	write("1-5", map[string]string{"idVendor": "0781", "idProduct": "5567"}) // no serial
	write("1-4:1.0", map[string]string{})                                    // an INTERFACE, not a device
	write("usb1", map[string]string{})                                       // a root hub entry with no ids
	return root
}

// TestSysfsReportsDevicesAndNotInterfaces is the filtering rule that keeps one stick from looking like
// several events.
func TestSysfsReportsDevicesAndNotInterfaces(t *testing.T) {
	got, err := usb.SysfsSource{Root: fixture(t)}.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d devices, want 2 (the interface and the id-less entry must be skipped): %+v", len(got), got)
	}
	bySerial := map[string]usb.Device{}
	for _, d := range got {
		bySerial[d.Serial] = d
	}
	if d, ok := bySerial["ABC123"]; !ok || d.VendorID != "0bda" || d.ProductID != "5411" {
		t.Errorf("the identified device is wrong: %+v", got)
	}
	// A device with NO serial is still reported: missing serials are common, and dropping them would
	// blind the connector to a whole class of hardware.
	if d, ok := bySerial[""]; !ok || d.VendorID != "0781" {
		t.Errorf("a device with no serial was dropped: %+v", got)
	}
}

// TestSysfsOnAHostWithoutUSBIsNotAnError — a VM with no USB subsystem is a host with no USB, not a
// broken one.
func TestSysfsOnAHostWithoutUSBIsNotAnError(t *testing.T) {
	got, err := usb.SysfsSource{Root: filepath.Join(t.TempDir(), "absent")}.Devices()
	if err != nil {
		t.Errorf("an absent USB subsystem reported an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d devices from an absent tree", len(got))
	}
}

// TestTheRawSerialNeverLeavesTheProducer is the D23 discipline, asserted at the boundary.
func TestTheRawSerialNeverLeavesTheProducer(t *testing.T) {
	p := usb.NewProducer("agent-1", []byte("pseudonym-key-0123456789abcdef"))
	evs, err := p.Produce(usb.SysfsSource{Root: fixture(t)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("no events produced from a populated tree")
	}
	for _, e := range evs {
		u := e.GetUsb()
		if u == nil {
			t.Fatalf("event %q carries no USB subject", e.GetEventId())
		}
		if u.GetSerialPseudonym() == "ABC123" {
			t.Error("the RAW serial reached the event. A USB serial is a durable device identifier that " +
				"re-identifies a person across contexts, and the event stream is the most copied, " +
				"retained and queried artefact in the system (D23)")
		}
	}
}
