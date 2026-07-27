# usb-enforcement Specification

## Purpose
A USB producer emitting pseudonymised-serial events and a USB enforcer that enacts a Decision via the
kernel `authorized_default` posture, exercising the Enforcer contract (D14) against a real enforcement
point (D1).

> **THE CAPABILITY IS NOW WHOLE (D313), after three separate gaps each of which alone made the claim
> above false.** Between D295 and D312 this section said "the first real (non-stub) enforcer ... proving
> the Enforcer contract end to end", while: nothing in the product could OBSERVE an attachment (fixed
> D312), the policy input never carried the USB SUBJECT so no rule could match a device (fixed D313), and
> no binary REGISTERED the enforcer so a BLOCK had nothing to carry it out (fixed D313). Each half had
> passing unit tests throughout.
>
> **A design error the integration test caught (D313).** The enforcer advertised ALLOW and enacted it by
> re-authorising the controller. That is coherent for one decision and incoherent for a stream: the switch
> is a MACHINE-WIDE latch while decisions are PER DEVICE, so a permitted keyboard's ALLOW released a
> banned stick's BLOCK microseconds later, and the posture reflected whichever device was polled last. It
> was the only enforcer in the tree advertising ALLOW — the tell, since ALLOW is the absence of
> containment. ALLOW was removed; BLOCK latches; `openshield-provision usb-authorize` clears it.
>
> **Honest limits.** The kernel switch is per-CONTROLLER, so a BLOCK deauthorises every device attached
> afterwards, not only the offending one — a per-device posture needs a udev rule per device id and is
> not attempted. Enforcement needs root and is opt-in via `OPENSHIELD_USB_ENFORCE`, deliberately separate
> from `OPENSHIELD_ENFORCE`: deciding which hardware a machine accepts is not a consequence of enabling
> file containment. Polling can miss a device attached and removed between two ticks.

## Requirements
### Requirement: USB events carry a pseudonymised serial
The USB producer MUST emit `USB_INSERTED` events whose serial is pseudonymised before the event is
created; the raw device serial MUST NOT enter the event stream.

The event stream is the most widely copied, retained and queried artefact in the system (D23). A
raw USB serial is a durable device identifier that can re-identify a person across contexts; it
must be pseudonymised at the source, the same discipline the user identity already follows.

#### Scenario: The raw serial never appears in an event
- **WHEN** the producer emits an event for a device with a known raw serial
- **THEN** the event's `serial_pseudonym` is not the raw serial
- **AND** a test asserts the raw serial appears nowhere in the event, and that the same device
  yields the same pseudonym (stable correlation) while differing from the raw value

### Requirement: The USB enforcer changes a real authorization posture
The enforcer MUST implement the `Enforcer` contract, advertise the actions it can carry out, and
enact a Decision by setting the kernel USB `authorized_default` posture. It MUST refuse an action
it does not advertise rather than silently doing nothing.

D1 asked for a real enforcer, not a stub, so the enforcement plugin shape is exercised against an
actual enforcement point. A silent no-op on an unhandled action is an enforcement that did not
happen but looks like it did — the quiet failure the audit trail exists to prevent.

#### Scenario: BLOCK latches the restrictive posture and ALLOW is not enacted
- **WHEN** the enforcer enforces a BLOCK Decision, then an ALLOW Decision
- **THEN** BLOCK sets `authorized_default` to deauthorise-by-default, and ALLOW is REFUSED as an
  unadvertised action, leaving the posture as the BLOCK left it
- **AND** a test asserts both via a fake authorizer, because enacting ALLOW means undoing containment:
  a stream of ordinary permitted devices would release a block nobody chose to release

#### Scenario: A blocked machine can be recovered
- **WHEN** an operator runs `openshield-provision usb-authorize` on a host whose posture is latched shut
- **THEN** the controllers are authorised again and the change is reported per controller
- **AND** an integration scenario asserts it, because a containment action the product can take and
  cannot undo is one an operator is right to refuse to enable (D293)

#### Scenario: The real kernel accepts the write
- **WHEN** the authorizer runs as root against `/sys/bus/usb/devices` on a machine with USB controllers
- **THEN** every controller's `authorized_default` reads back the written value, and the original posture
  is restored afterwards
- **AND** this is root-gated and skips elsewhere, because it is the only test that can prove the
  hardcoded sysfs path and glob are right — every other test supplies its own Root

#### Scenario: An unadvertised action is refused, not no-oped
- **WHEN** the enforcer is asked to enforce an action it does not advertise
- **THEN** it returns an error naming the action
- **AND** it does not change the posture

### Requirement: The enforcer sees only the Decision, end to end
A USB event MUST flow through the real pipeline to a Decision, and that Decision alone MUST be what
the enforcer acts on — it MUST NOT receive the event, the classification, or any handle to them.

The CrowdSec separation (D14) is what lets enforcement points be written independently of
detection. Proving it with a real event, a real policy Decision and a real enforcer is stronger
than asserting the interface shape.

#### Scenario: Event to enforcement through the real policy
- **WHEN** a USB event is dispatched through the shipped policy to a Decision, and that Decision is
  handed to the enforcer
- **THEN** the enforcer enacts it, having received only the Decision
- **AND** a test drives the full path and asserts the enforcement point changed


### Requirement: A USB event is visible to policy
The policy input MUST carry the USB device's vendor id, product id and pseudonymised serial, so an
operator can write a rule that matches a device model.

Without it a policy cannot tell a memory stick from a file write. The default policy's own comment told
operators that one who wants USB to block "writes that rule", and named a rule that could not be written:
the subject reached Rego never, and `GetUsb` had exactly one non-generated caller in the tree — a log
line. The device MODEL is what is exposed; the serial arrives already pseudonymised (D23), so a rule can
say "the same device again" without the engine ever holding the real serial.

#### Scenario: A policy blocks one device model and permits another
- **WHEN** two devices of different vendors are attached and a policy blocks one vendor id
- **THEN** the banned device's Decision is BLOCK and the permitted device's is ALLOW
- **AND** an integration scenario drives the real engine and asserts the controller posture, with both
  devices present — a scenario with only the banned one would pass against an enforcer that blocks
  everything, which is the likelier bug and the worse one to ship

### Requirement: A USB event's identity is the whole device
The event id MUST be derived from the device's vendor, product AND serial together, keyed, so that
devices without a serial remain distinguishable.

Keying it on the serial alone made every serial-less device — a hub, a webcam, most keyboards — arrive
with the identical event id `usb-`. The ledger keys on event_id and the decision projection joins on it,
so a common case, not an edge case, collapsed into one entity. The honest limit: two identical models
with no serial are still one id, because sysfs offers nothing else identifying the DEVICE; the bus path
is a POSITION, and keying on it would make the same stick a different device in a different port.

#### Scenario: Two serial-less devices are distinct
- **WHEN** a hub and a webcam, neither carrying a serial, produce events
- **THEN** their event ids differ, neither is the degenerate `usb-`, and the same device yields the same
  id twice
- **AND** a test asserts the id is KEYED: two producers with different keys yield different ids, or the
  low-entropy serial behind it would be brute-forceable from the audit trail alone
