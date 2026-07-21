## Context

The proto already has `EVENT_KIND_USB_INSERTED` and `UsbSubject {vendor_id, product_id,
serial_pseudonym}`. `core.Enforcer` is `{ Capabilities() []Action; Enforce(ctx, *Decision) error }`
with `core.CanEnforce`. The Decision carries `event_id` and the action but NO enforcement target.
Linux exposes global USB authorisation at `/sys/bus/usb/devices/usbN/authorized_default` (0/1),
the mechanism USBGuard builds on.

## Goals / Non-Goals

**Goals:**
- Produce `USB_INSERTED` events with a pseudonymised serial.
- A real `core.Enforcer` that changes `authorized_default`, tested without privilege plus a
  privileged integration path.
- Prove Event → policy → Decision → enforcement end to end, enforcer seeing only the Decision.

**Non-Goals:**
- Per-device enforcement (needs a Decision target — deferred, D26).
- The fail-open/blocking contract (T-011).
- Wiring enforcers into the live observe-only pipeline (Phase 2).

## Decisions

### The producer pseudonymises the serial at the source
`connectors/usb`: `DeviceSource` yields raw device descriptors `{vendor, product, serial}`. The
producer maps `serial` → `serial_pseudonym` with a keyed hash before it ever reaches an Event, so
the raw serial never enters the event stream (D23). The pseudonym is stable (same device → same
pseudonym) so repeated insertions correlate, but is not reversible without the key. Vendor/product
IDs are not personal data and pass through.

### The enforcer is `authorized_default`, behind an interface
`enforcers/usb`: `Enforcer{ auth USBAuthorizer }`.
- `Capabilities() -> {ACTION_ALLOW, ACTION_BLOCK}` — the two postures it can set.
- `Enforce(d)`: BLOCK → `auth.SetDefaultAuthorized(false)`; ALLOW → `SetDefaultAuthorized(true)`;
  any other action → an error naming it (an enforcer must refuse an action it does not advertise,
  not silently no-op — a silent no-op is an enforcement that did not happen but looks like it did).
- `USBAuthorizer` interface `{ SetDefaultAuthorized(bool) error }`. The sysfs implementation writes
  every USB controller's `authorized_default`; a fake records calls for tests.

### End-to-end proof uses the real policy
A USB event has no classification (no file content), so the shipped default policy's alerting rule
does not fire and it returns ALLOW with a reason — a real Decision from the real policy. The test
dispatches the USB event, takes that Decision, confirms `CanEnforce`, and enforces, asserting the
fake authorizer was set permissive. A separate unit test constructs a BLOCK Decision and asserts
the authorizer was set restrictive — proving the enforcer can carry out BLOCK even though Phase-1
policy never emits it.

### Privileged integration, loud skip
A build-tagged test writes a real `authorized_default` if running as root with USB controllers
present, and t.Skip's LOUDLY otherwise — the decision logic is what CI proves; the sysfs write is a
few bytes and is spike-level.

## Risks / Trade-offs

- **Global posture, not per-device.** Stated in the proposal; per-device is the deferred D26
  addition. `authorized_default` is exactly what D1 named ("via authorized_default"), so this is
  the intended scope, not a shortcut.
- **A stable pseudonym still correlates a device across insertions.** That is intended (repeat-USB
  detection needs it) and is the same trade the pseudonymous user id makes (D23); it is not
  reversible without the key.
- **Writing authorized_default=0 on a live machine deauthorises the operator's own devices.** The
  enforcer is not wired into the live pipeline in Phase 1, and the privileged test restores the
  prior value; a real deployment must treat this as the blunt instrument it is (global, not
  targeted).
- **The enforcer is not invoked by the live pipeline yet.** By design (D1). The contract is proven
  by test; Phase 2 wires it.
