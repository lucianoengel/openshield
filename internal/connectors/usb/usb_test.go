package usb_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/usb"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"google.golang.org/protobuf/proto"
)

// The raw serial — a durable device identifier — must never enter the event
// stream (D23). It is pseudonymised at the source.
func TestSerialIsPseudonymised(t *testing.T) {
	const raw = "SN-DEADBEEF-0001"
	p := usb.NewProducer("agent-1", []byte("pseudonym-key"))
	dev := usb.Device{VendorID: "1d6b", ProductID: "0002", Serial: raw}

	e := p.Event(dev, 0)

	// The raw serial must appear NOWHERE in the serialized event.
	b, err := proto.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), raw) {
		t.Errorf("raw serial %q appears in the event — it must be pseudonymised at the source", raw)
	}
	got := e.GetUsb().GetSerialPseudonym()
	if got == "" || got == raw {
		t.Errorf("serial_pseudonym = %q, want a non-empty pseudonym distinct from the raw serial", got)
	}
	if e.GetKind() != corev1.EventKind_EVENT_KIND_USB_INSERTED {
		t.Errorf("kind = %v, want USB_INSERTED", e.GetKind())
	}
	// Vendor/product are not personal data and pass through.
	if e.GetUsb().GetVendorId() != "1d6b" {
		t.Errorf("vendor id lost: %q", e.GetUsb().GetVendorId())
	}

	// Stable: the same device correlates across insertions.
	e2 := p.Event(dev, 1)
	if e2.GetUsb().GetSerialPseudonym() != got {
		t.Error("the same device produced different pseudonyms — repeat-USB correlation is lost")
	}
	// Keyed: a different key yields a different pseudonym (not a bare hash).
	p2 := usb.NewProducer("agent-1", []byte("different-key"))
	if p2.Event(dev, 0).GetUsb().GetSerialPseudonym() == got {
		t.Error("the pseudonym does not depend on the key — a bare hash of a low-entropy serial is reversible")
	}
}

// TestSeriallessDevicesAreDistinctEvents is D313's fix, and the defect it fixes was found by running the
// product rather than by reading it: a fixture tree produced three devices and the ledger showed the event
// id "usb-" twice.
//
// Serials are ABSENT on most USB hardware — hubs, webcams, the average keyboard. Keying the event id on
// the serial alone therefore collapsed the common case, not an edge case, into a single identity.
func TestSeriallessDevicesAreDistinctEvents(t *testing.T) {
	p := usb.NewProducer("agent-1", []byte("0123456789abcdef0123456789abcdef"))
	hub := p.Event(usb.Device{VendorID: "1d6b", ProductID: "0002"}, 0)
	cam := p.Event(usb.Device{VendorID: "046d", ProductID: "0825"}, 1)

	if hub.GetEventId() == cam.GetEventId() {
		t.Fatalf("a hub and a webcam — different models, both without a serial — share the event id %q. "+
			"The ledger keys on event_id and the decision projection joins on it, so every serial-less "+
			"device on the machine would read as one entity", hub.GetEventId())
	}
	if hub.GetEventId() == "usb-" || cam.GetEventId() == "usb-" {
		t.Errorf("a serial-less device got the degenerate event id %q", hub.GetEventId())
	}
	// STABLE for the same device, or repeat-device correlation cannot work: the point of a keyed
	// pseudonym is that the SAME stick is recognisable across insertions.
	if again := p.Event(usb.Device{VendorID: "1d6b", ProductID: "0002"}, 7); again.GetEventId() != hub.GetEventId() {
		t.Errorf("the same device produced two different event ids (%q then %q) — a device that is never "+
			"the same device twice cannot be correlated across insertions",
			hub.GetEventId(), again.GetEventId())
	}
}

// TestTheEventIdDoesNotLeakTheSerial. The id is derived from the serial, so it is worth asserting the
// derivation is the KEYED one: an id built by concatenation would put the serial an operator's hardware
// asset register can look up straight into every audit row, which is the exact re-identification D23's
// pseudonymisation exists to prevent.
func TestTheEventIdDoesNotLeakTheSerial(t *testing.T) {
	const serial = "SERIAL-NOT-IN-THE-ID"
	p := usb.NewProducer("agent-1", []byte("0123456789abcdef0123456789abcdef"))
	e := p.Event(usb.Device{VendorID: "0781", ProductID: "5567", Serial: serial}, 0)
	if strings.Contains(e.GetEventId(), serial) {
		t.Errorf("the event id %q contains the raw serial", e.GetEventId())
	}
	if strings.Contains(e.GetUsb().GetSerialPseudonym(), serial) {
		t.Errorf("the pseudonym %q contains the raw serial", e.GetUsb().GetSerialPseudonym())
	}
	// Distinct KEYS must give distinct ids, or the pseudonym is a plain hash and the low-entropy serial
	// is brute-forceable by anyone holding the audit trail.
	q := usb.NewProducer("agent-1", []byte("ffffffffffffffffffffffffffffffff"))
	if q.Event(usb.Device{VendorID: "0781", ProductID: "5567", Serial: serial}, 0).GetEventId() == e.GetEventId() {
		t.Error("two producers with DIFFERENT keys produced the same event id — the id is not keyed, so " +
			"the serial behind it is brute-forceable from the audit trail alone")
	}
}
