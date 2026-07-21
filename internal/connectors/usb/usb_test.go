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
