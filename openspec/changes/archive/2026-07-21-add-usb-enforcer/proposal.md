# Add the USB event producer and a real USB enforcer (T-020)

## Why

D1 called for shipping "one trivial USB enforcer to prove the interface" — a REAL enforcement
point, not a stub, so the `Enforcer` contract is exercised end to end rather than only asserted.
That was silently dropped in the first ticket pass and is restored here. Everything downstream of
a Decision — the closed action set (D14), the CrowdSec separation, the enforcer plugin shape —
is currently defined but never driven by an enforcer that actually changes something. This makes
one that does.

## What changes

**A USB event producer (`internal/connectors/usb`).** It emits `USB_INSERTED` events carrying a
`UsbSubject` (vendor id, product id, and a **pseudonymised** serial — never the raw serial, D23).
The device source is behind a `DeviceSource` interface so the producer is tested without real
hardware; the production source reads udev/sysfs.

**A real USB enforcer (`internal/enforcers/usb`) via `authorized_default`.** It implements
`core.Enforcer`, advertises the ALLOW and BLOCK actions, and carries a Decision out by writing the
kernel's global USB authorization posture: `/sys/bus/usb/devices/usbN/authorized_default` — `0`
means newly attached devices are deauthorised by default, `1` means permitted. This is a real,
standard Linux mechanism (the basis of USBGuard), so the enforcer changes an actual enforcement
point, not a simulated one. The sysfs write is behind a `USBAuthorizer` interface, so the
decision logic is tested without privilege and a privileged integration test exercises the real
write, skipping loudly otherwise.

**End to end, through the real pipeline.** A test runs a USB event through the dispatcher and the
shipped default policy to a Decision, then hands that Decision to the enforcer, which changes the
fake authorizer's state — Event → policy → Decision → enforcement point, with the enforcer seeing
ONLY the Decision (D14, guaranteed by the interface).

## What this does NOT claim or cover

- **It is NOT per-device enforcement.** `authorized_default` is a global posture (all new devices),
  not "deauthorise THIS device". Per-device enforcement would require the Decision to carry a typed
  enforcement TARGET — which it does not: a Decision carries `event_id` and the action, not the
  device. That is the small, identifiable core addition D26 predicts a new-shape capability needs,
  and it is deferred until per-device USB (or any targeted) enforcement is actually built, rather
  than added speculatively. Surfacing the gap is part of the ticket's value.
- **It does NOT test the fail-open / blocking contract** (A8). USB attach-time authorisation has
  no blocked process, no permission window and no timeout race — that contract is the fanotify
  watchdog's (T-011), and conflating them would prove neither.
- **Phase 1 does not enforce in the live pipeline** (D1). The dispatcher records Decisions and
  invokes no enforcer; the default policy emits ALLOW, never BLOCK. This ticket proves the enforcer
  CONTRACT works with a real mechanism — the enforcer can carry out BLOCK, and a test drives it —
  but wiring enforcers into the live pipeline is Phase 2.
- **It does not identify people from devices.** The serial is pseudonymised at the producer; the
  raw serial never enters the event stream.

## Decisions

Depends on **D1** (ship one trivial USB enforcer to prove the interface; observe-only), **D14**
(the enforcer sees only the Decision; the action set is closed and typed), **D23** (pseudonymous
subject — the USB serial included), and the T-008 policy that produces the Decision.

Establishes a small new decision: **the USB enforcer acts on the global `authorized_default`
posture; per-device enforcement is deferred because it requires a typed enforcement target on the
Decision (the D26-predicted core addition), added when targeted enforcement is actually built.**
