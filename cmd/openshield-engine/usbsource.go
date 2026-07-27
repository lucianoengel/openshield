package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/usb"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// USB OBSERVATION (D312) — the producer half, wired at last.
//
// `internal/connectors/usb` has shipped a producer and `internal/enforcers/usb` an enforcer since T-020,
// and no binary imported either. The capability spec called it "the first real (non-stub) enforcer ...
// proving the Enforcer contract end to end with an actual enforcement point", and the product could not
// observe a USB attachment at all: `DeviceSource` had only a test fake until D312 gave it sysfs.
//
// POLLING, NOT UDEV, and the trade is worth naming: a udev netlink subscription would see an attachment
// the instant it happens, and would also mean a second event source, a socket to own and a privilege
// question. Polling sysfs is unprivileged (D52's reasoning applied to USB) and cannot miss a device that
// STAYS attached — which is the case that matters for "what was plugged into this machine". It CAN miss
// a device attached and removed entirely between two ticks; that is stated rather than hidden.

// usbSource emits an event for each NEWLY attached device on a timer.
func usbSource(ctx context.Context, agentID string, key []byte, interval time.Duration,
	events chan<- *corev1.Event, log *slog.Logger) {
	p := usb.NewProducer(agentID, key)
	// The sysfs root is overridable so a scenario can point at a fixture tree. A build host has whatever
	// devices it happens to have, and asserting on those would be asserting on the machine.
	src := usb.SysfsSource{Root: os.Getenv("OPENSHIELD_USB_SYSFS")}
	// seen keys on the pseudonym plus the vendor/product, so re-reading the SAME attached device on
	// every tick does not re-emit. Without it a plugged-in stick would produce an event per tick for as
	// long as it stays plugged in, which is a detector nobody can read.
	seen := map[string]bool{}
	var seq uint64
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		evs, err := p.Produce(src, seq)
		if err != nil {
			log.Warn("usb: reading attached devices failed", slog.String("err", err.Error()))
		}
		for _, e := range evs {
			u := e.GetUsb()
			k := u.GetVendorId() + ":" + u.GetProductId() + ":" + u.GetSerialPseudonym()
			if seen[k] {
				continue
			}
			seen[k] = true
			seq++
			select {
			case events <- e:
				log.Info("usb: device observed", slog.String("vendor", u.GetVendorId()),
					slog.String("product", u.GetProductId()))
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// usbPseudonymKey returns the key that pseudonymises serials, generating an ephemeral one when the
// operator has not supplied a persistent one.
//
// A GENERATED KEY IS ANNOUNCED, because the consequence is not obvious: the pseudonym is stable only for
// this process's lifetime, so the same stick reads as a different device after a restart and
// repeat-USB detection cannot work across one. That is a real limitation of running without a
// configured key, and an operator should learn it from the log rather than from a report that never
// correlates.
func usbPseudonymKey(log *slog.Logger) []byte {
	if p := os.Getenv("OPENSHIELD_USB_PSEUDONYM_KEY"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			fatal(log, "reading the USB pseudonym key", err)
		}
		if len(b) < 16 {
			log.Warn("usb: the configured pseudonym key is very short; a low-entropy key makes a " +
				"pseudonymised serial brute-forceable, which is the whole reason the HMAC is keyed")
		}
		return b
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		fatal(log, "generating a USB pseudonym key", err)
	}
	log.Warn("usb: OPENSHIELD_USB_PSEUDONYM_KEY unset — using an EPHEMERAL key. Serial pseudonyms are " +
		"then stable only for this process's lifetime, so the same device reads as a new one after a " +
		"restart and repeat-device correlation cannot work across restarts")
	return k
}
