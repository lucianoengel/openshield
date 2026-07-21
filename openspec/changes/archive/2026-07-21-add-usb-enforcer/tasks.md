## 1. USB event producer

- [x] 1.1 `internal/connectors/usb`: `DeviceSource` interface yielding {vendor, product, serial};
      producer maps serial → serial_pseudonym via a keyed hash BEFORE building the Event
- [x] 1.2 Emit `EVENT_KIND_USB_INSERTED` events with `UsbSubject{vendor_id, product_id,
      serial_pseudonym}`
- [x] 1.3 **Test**: the raw serial appears nowhere in the event; same device → same pseudonym;
      pseudonym != raw. `TestSerialIsPseudonymised`

## 2. USB enforcer

- [x] 2.1 `internal/enforcers/usb`: `Enforcer{auth USBAuthorizer}` implementing `core.Enforcer`;
      `Capabilities` = {ALLOW, BLOCK}
- [x] 2.2 `Enforce`: BLOCK → SetDefaultAuthorized(false); ALLOW → true; other → error naming it
- [x] 2.3 `USBAuthorizer` interface + a sysfs implementation writing `authorized_default`
- [x] 2.4 **Test**: BLOCK sets restrictive, ALLOW permissive; an unadvertised action errors and
      changes nothing. `TestEnforcePostures`, `TestUnadvertisedActionRefused`

## 3. End to end

- [x] 3.1 **Test**: USB event → dispatcher + shipped default policy → Decision → CanEnforce →
      Enforce changes the fake authorizer. `TestUSBEventToEnforcement`
- [x] 3.2 **Test**: a constructed BLOCK Decision is carried out (enforcer can BLOCK though Phase-1
      policy never emits it). `TestEnforcerCanBlock`

## 4. Privileged integration + docs

- [x] 4.1 Build-tagged test writing real `authorized_default` as root with USB controllers present;
      restores the prior value; SKIPS LOUDLY otherwise
- [x] 4.2 Note in `docs/decisions.md` (new D-number): USB enforcer via authorized_default (global);
      per-device deferred pending a Decision enforcement-target (D26)
- [x] 4.3 Mark T-020 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| unadvertised action no-ops instead of erroring | `TestUnadvertisedActionRefused` (compiling no-op) |
| BLOCK sets the permissive posture | `TestEnforcePostures`, `TestEnforcerCanBlock` |
| raw serial emitted into the event | `TestSerialIsPseudonymised` (wire-byte scan) |

The producer pseudonymises the serial with a keyed HMAC (a bare hash of a
low-entropy serial is reversible), proven by scanning the serialized event for
the raw value, checking stability across insertions, and that the pseudonym
depends on the key. The enforcer changes a real posture via a `USBAuthorizer`
interface; `SysfsAuthorizer` is tested against a fake sysfs tree (no privilege)
and errors LOUDLY when no controllers are present (a no-op write must not look
like success). End to end runs a USB event through the SHIPPED default policy to
a real ALLOW Decision and into the enforcer, which sees only the Decision (D14).
The Decision-has-no-target boundary is recorded as D39, deferred per D26.
