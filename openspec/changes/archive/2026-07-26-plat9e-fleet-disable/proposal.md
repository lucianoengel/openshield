## Why

D265 shipped the emergency disable and named its own gap: the kill switch reaches server-side components
through the configuration store, and **endpoint agents do not read it**, so they could only be disabled
one host at a time by a local break-glass file. "Fleet-wide" that quietly excluded the endpoints is
exactly the overclaim this project's review rounds exist to catch, which is why it was named rather than
left to be discovered.

## What Changes

- **A signed `FleetControl` message** with a closed two-verb vocabulary (disable / restore), published on
  its own subject and consumed by the endpoint.
- **Deliberately NOT a fourth `IntentVerb`.** Every member of that vocabulary *causes* enforcement;
  "stop enforcing" is its opposite. Folding them together would give one message type whose members both
  start and stop the product's action, where a consumer mishandling the discriminator fails in the most
  dangerous available direction.
- **Three independent bounds, because this is the most attractive forgery target in the system** — one
  accepted message turns the product off everywhere:
  - the **signature** answers *who said this* (origin, not authority);
  - a **monotonic sequence** answers **replay** — a captured, genuinely signed disable verifies perfectly
    every time it is re-sent, and only a sequence bound refuses it;
  - **mandatory expiry** answers duration — a captured or forgotten disable cannot last.
- **Four-eyes on every disable**, with no high-impact/low-impact split as intents have, because there is
  no low-impact way to disable a security product fleet-wide. The approval binds to a **deterministic
  control id**, so an operator approves exactly the control that will be sent.
- **Everything refused leaves enforcement ON.**

## Capabilities

### Modified Capabilities
- `enforcement`: the fleet-wide emergency disable now reaches endpoint agents over the signed channel.

## Impact

- **Proto change**: `FleetVerb` + `FleetControl` (additive); a new NATS subject.
- **New code**: `internal/intent/fleetcontrol.go` (consumer), `internal/controlplane/fleetcontrol.go`
  (publisher), `Engine.SubscribeFleetControl`.
- **No migration** — the monotonic sequence is stored in the existing settings table.
- **Honest scope**: the control plane still cannot *confirm* a fleet is disabled — publication is
  best-effort pub/sub, and an agent that was offline applies it when it reconnects only if the message is
  still within its TTL. Confirming fleet state needs an acknowledgement path, which is a separate ticket.
  Signing proves origin, not authority: four-eyes and the TTL **bound** a compromised control plane rather
  than preventing it. The gateway consumes the same message type but is not wired here.
