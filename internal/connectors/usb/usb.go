// Package usb is the USB_INSERTED event producer (T-020).
//
// A connector's whole job is to emit Events; it never classifies, decides or
// enforces. This one turns a USB device attachment into an Event carrying a
// UsbSubject — vendor, product, and a PSEUDONYMISED serial. The raw serial is a
// durable device identifier that can re-identify a person across contexts, so it
// is pseudonymised at the source, before it ever enters the event stream, the
// same discipline the user identity follows (D23).
package usb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Device is a raw descriptor from the source. The RAW serial lives only here and
// in the source; it must not reach an Event.
type Device struct {
	VendorID  string
	ProductID string
	Serial    string
}

// DeviceSource yields attached devices. Behind an interface so the producer is
// tested without hardware; production reads udev/sysfs.
type DeviceSource interface {
	Devices() ([]Device, error)
}

// Producer emits USB events. It holds the pseudonymisation key, which never
// leaves the agent.
type Producer struct {
	AgentID     string
	ConnectorID string
	key         []byte
	now         func() *timestamppb.Timestamp
}

// NewProducer creates a producer with a serial-pseudonymisation key.
func NewProducer(agentID string, pseudonymKey []byte) *Producer {
	return &Producer{
		AgentID:     agentID,
		ConnectorID: "usb",
		key:         pseudonymKey,
		now:         timestamppb.Now,
	}
}

// pseudonymiseSerial maps a raw serial to a stable, non-reversible pseudonym.
// Keyed HMAC, not a bare hash: a bare SHA-256 of a serial is brute-forceable
// (serials are low-entropy), and the key is what makes the pseudonym irreversible
// to anyone who does not hold it. Stable, so the same device correlates across
// insertions (repeat-USB detection needs that); not reversible without the key.
func (p *Producer) pseudonymiseSerial(raw string) string {
	if raw == "" {
		return ""
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(raw))
	return "usbser_" + hex.EncodeToString(mac.Sum(nil)[:12])
}

// deviceID is the event id: a keyed digest of the device's WHOLE identity, not of its serial alone.
//
// Keying it on the serial alone was a real defect (D313): a device with no serial pseudonymises to the
// empty string, so every serial-less device — a hub, a webcam, most keyboards — arrived with the event id
// "usb-". The ledger keys on event_id and the decision projection joins on it, so an entire class of
// hardware collapsed into ONE entity: the second hub's decision would look like a second decision about
// the first one.
//
// THE HONEST LIMIT: two identical models with no serial are still one id, because sysfs offers nothing
// else that identifies the DEVICE. The bus path would separate them, but a path is a POSITION — keying on
// it would make the same stick a different device in a different port, which breaks the repeat-device
// correlation the pseudonym exists for. Indistinguishable hardware reads as indistinguishable.
func (p *Producer) deviceID(d Device) string {
	mac := hmac.New(sha256.New, p.key)
	// Length-prefixed, so ("ab","c") and ("a","bc") are different identities rather than the same joined
	// string — the classic concatenation ambiguity, and vendor/product ids are exactly the fixed-width
	// fields where it is easy to assume it cannot happen.
	for _, f := range []string{d.VendorID, d.ProductID, d.Serial} {
		fmt.Fprintf(mac, "%d:%s", len(f), f)
	}
	return "usb-" + hex.EncodeToString(mac.Sum(nil)[:12])
}

// Event builds a USB_INSERTED event for a device, pseudonymising the serial
// BEFORE the event exists.
func (p *Producer) Event(d Device, seq uint64) *corev1.Event {
	return &corev1.Event{
		EventId:     p.deviceID(d),
		AgentId:     p.AgentID,
		ConnectorId: p.ConnectorID,
		Sequence:    seq,
		ObservedAt:  p.now(),
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Kind:        corev1.EventKind_EVENT_KIND_USB_INSERTED,
		Target: &corev1.Event_Usb{Usb: &corev1.UsbSubject{
			VendorId:        d.VendorID,
			ProductId:       d.ProductID,
			SerialPseudonym: p.pseudonymiseSerial(d.Serial),
		}},
	}
}

// Produce emits an event per attached device, assigning sequences from start.
func (p *Producer) Produce(src DeviceSource, start uint64) ([]*corev1.Event, error) {
	devs, err := src.Devices()
	if err != nil {
		return nil, err
	}
	out := make([]*corev1.Event, 0, len(devs))
	for i, d := range devs {
		out = append(out, p.Event(d, start+uint64(i)))
	}
	return out, nil
}
