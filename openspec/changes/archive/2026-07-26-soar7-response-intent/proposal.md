## Why

OpenShield can detect and correlate; it cannot yet *respond*. Two MVP items are blocked on the same missing
piece: XDR-6 (one approved `CONTAIN(entity)` enacted by both gateway and endpoint) and HIPS-3 increment 2b
(the exec gate denying a contained entity's next exec). Both need a way for the control plane to say
"this subject is contained" that an endpoint can act on **without the server commanding it**.

That distinction is the whole design. The server publishes DATA; the local policy decides (T2/D14) — the
same shape as the risk updates already flowing to gateways (D91). An open command channel would let a
compromised control plane express "run this", which is precisely what the closed action set exists to make
unexpressible.

## What Changes

- **A closed Response-Intent vocabulary** — `ELEVATE_SCRUTINY`, `CONTAIN`, `REVOKE_TRUST` — carried in a
  signed, versioned, TTL'd message. Three verbs, and adding a fourth is a deliberate owner decision, not a
  config change.
- **`PublishIntent`**, mirroring `PublishRisk`: ed25519-signed by the control plane so a subscriber can tell
  a real intent from a forged one, and refusing to publish unsigned.
- **Intents are consumed as typed policy CONTEXT**, not as instructions. A gateway or endpoint reads the
  current intent for a subject and its own policy decides what that means. **An endpoint whose policy
  ignores intents is unaffected** — that is a property, not an oversight.
- **High-impact intents require a four-eyes approval** (SOAR-3) and a **blast-radius guard**: an intent
  aimed at more subjects than a configured ceiling is refused before it is published.
- **Intents expire.** A `CONTAIN` with no TTL is a permanent quarantine nobody remembers issuing.

## Capabilities

### New Capabilities

- `response-intent`: the signed, closed-vocabulary, TTL'd intent seam — publication gated on approval and
  blast radius, consumption as verified policy context.

## Impact

- **Code:** proto (`ResponseIntent`), `internal/controlplane` (publish + gating), a subscriber and store on
  the consuming side, policy input.
- **Decisions:** implements **ADR-12 Tier-2**; depends on **D14** (closed vocabulary — the server never
  commands), **SEC-1/D91** (signed publication, the risk-update precedent), **SOAR-3** (four-eyes), and
  **D23** (pseudonymous subjects).

### What this change does NOT claim or cover

- **It does not enact anything.** Publishing an intent changes no flow and denies no exec by itself; the
  consumers do that. XDR-6 wires the gateway and endpoint enactment, and HIPS-3 inc 2b wires the exec gate.
  Until those land, an intent is a signal nobody acts on — stated so this is not mistaken for containment.
- **It is not an instruction channel and must never become one.** The vocabulary is closed at three verbs
  precisely so a compromised control plane cannot express an arbitrary action. Any new verb is a one-at-a-
  time owner decision (ADR-12).
- **A subscriber that ignores intents is unaffected**, by design. That means coverage depends on every
  consumer opting in, and an unpatched endpoint silently provides no containment — an honest limit of a
  data-not-command model.
- **Signing proves origin, not authority.** A validly signed intent from a compromised control plane is
  indistinguishable from a legitimate one; four-eyes and the blast-radius ceiling bound the damage rather
  than prevent it, and neither survives an attacker who holds both the signing key and an operator cert.
- No revocation list: an intent is undone by expiry or by a superseding intent, not by a recall message.
