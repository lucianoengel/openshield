## Why

**This change documents behaviour that already shipped** (D254, commit `455b4c5`). Like its endpoint
counterpart, XDR-6 was implemented without an OpenSpec change, so the `response-intent` capability never
received a delta describing the coordination property the ticket exists for.

The behaviour: ONE approved `CONTAIN` intent is enacted by BOTH domains — the gateway blocks the entity's
flows, the endpoint denies its executions — each by its own local policy, both traceable to one intent id,
and both released when the intent expires.

## What Changes

Nothing in the code. The spec gains what the code already does:

- One intent, **two independent local decisions** in different domains.
- Both enactments carry **the same intent id**, and they do so through the field that already reaches the
  ledger — so correlating two enactments of one containment needed **no new hashed column**.
- **Expiry releases both.**

## Capabilities

### Modified Capabilities

- `response-intent`: one intent is enacted across domains under a single traceable id, and lapses from both.

## Impact

- **Docs only.** The implementation is at `455b4c5`.
- **Decisions:** documents **D254**; depends on **D252** (the signed seam), **D253** (endpoint enactment),
  **D27** (`context_version` as the recorded Context identity), and migration 001's warning that adding a
  hashed ledger column breaks chain continuity.

### What this change does NOT claim or cover

- It adds no capability; where delta and code disagree, the code at `455b4c5` is the truth.
- The gateway blocks only what crosses it: an entity with a path that avoids the gateway is not blocked by
  it, and the endpoint half depends on a live engine (fail-open).
- A policy that does not read the intent is unaffected in ITS domain — so containment can be partial, with
  one domain enacting and the other silently not.
