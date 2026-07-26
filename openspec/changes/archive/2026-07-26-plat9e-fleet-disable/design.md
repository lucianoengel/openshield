## Context

D265's kill switch is driven by a local file and by a dynamic configuration setting. Endpoint agents read
neither the settings store nor a fleet-wide channel for this, so their disable was per-host.

## Goals / Non-Goals

**Goals:** a signed fleet control the endpoint consumes; replay and duration bounds; four-eyes on disable;
fail toward enforcing.

**Non-Goals:** acknowledgement of fleet state; gateway wiring; any change to what the switch does once
engaged.

## Decisions

### Its own vocabulary, not a fourth IntentVerb

This was the open question left in D265, and the answer is separation. Every `IntentVerb` causes
enforcement — contain, revoke trust, elevate scrutiny. "Stop enforcing" is the opposite instruction, and
merging them produces one signed type whose members both start and stop the product's action. A consumer
that mishandles the discriminator then fails toward *disabled*, which is the worst available direction.
Two types cost a proto message and remove that class of bug entirely.

### Three bounds, because the signature alone is not enough

Each answers a different attack, and the middle one is the one usually missed: a **captured, genuinely
signed** disable verifies perfectly every time it is replayed. Only a monotonic sequence refuses it — and
the sequence is stored, not held in memory, because a control-plane restart that reset it would re-open
the replay window on every consumer simultaneously.

Expiry answers the third: a disable that cannot lapse is a product that is off with nobody remembering
having turned it off.

### Four-eyes with no impact split

Intents gate only high-impact verbs, deliberately, because gating everything trains operators to
rubber-stamp. That reasoning does not transfer: there is exactly one fleet-disable verb and it turns the
product off everywhere, so there is nothing to be selective about. The approval binds to a **deterministic**
control id derived from verb and sequence, so an operator approves the specific control that will be sent
rather than "a disable" in the abstract.

### Fail toward enforcing, consistently with the switch it drives

Unverifiable, replayed, expired, unknown-version, no-verb — all refused, all leaving enforcement on. The
consumer never partially applies a control it did not fully understand.

## Risks / Trade-offs

- **Best-effort delivery** → the control plane cannot confirm a fleet is disabled; an agent offline past
  the TTL never applies it. Stated, and an acknowledgement path is a separate ticket rather than implied.
- **Signing proves origin, not authority** → four-eyes and the TTL bound a compromised control plane, they
  do not prevent it; the same limit recorded for SOAR-7.
- **A short TTL means re-issuing** → deliberate: cheap, and the alternative is a disable nobody revisits.

## Migration Plan

Additive proto and a new subject; the sequence rides the existing settings table. A deployment that never
publishes a control is unaffected.

## Open Questions

- Whether the gateway should consume the same message or continue to take its disable from configuration —
  it reads the settings store already, so the marginal value is small and it is left out rather than added
  speculatively.
