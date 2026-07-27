# usb-enforcement Specification

## Purpose
A USB producer emitting pseudonymised-serial events and a USB enforcer that enacts a Decision via the
kernel `authorized_default` posture, exercising the Enforcer contract (D14) against a real enforcement
point (D1).

> **OBSERVATION IS NOW REACHABLE (D312); ENFORCEMENT IS NOT YET WIRED.** The producer reads real devices
> from `/sys/bus/usb/devices` and `openshield-engine` polls it when `OPENSHIELD_USB_INTERVAL` is set, so
> an attachment becomes an event, is pseudonymised at the source, decided by policy and recorded. The
> default policy ALERTS on it and deliberately does not block: the same event fires for a keyboard, a
> webcam and a hub.
>
> **What is still absent:** no binary registers the USB ENFORCER, so a BLOCK decision has nothing to
> carry it out — setting `authorized_default` needs root, and which hosts should run a privileged USB
> posture is a deployment decision this project has not made. The requirement below describing enforcement
> is therefore intent, not shipped behaviour.
>
> Between D295 and D312 this section claimed "the first real (non-stub) enforcer ... proving the Enforcer
> contract end to end", while nothing in the product could observe a USB attachment at all. Half of that
> is now true; the sentence stays corrected rather than restored.
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

#### Scenario: BLOCK sets the restrictive posture, ALLOW the permissive one
- **WHEN** the enforcer enforces a BLOCK Decision, then an ALLOW Decision
- **THEN** it sets `authorized_default` to deauthorise-by-default, then to authorise
- **AND** tests assert both via a fake authorizer

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

