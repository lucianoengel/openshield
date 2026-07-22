## Context

`Engine.Process(ctx, ev)` dispatches an event through classify → policy → audit. The connectors build
events with a Target but no Subject and no observed_at; `ValidateEvent` (which requires event_id,
observed_at, subject, purpose, target) is never called. XDR-3 makes the engine the place where an
endpoint event is attributed and validated, because the engine is where the device identity is known.

## Goals / Non-Goals

**Goals**
- `Engine.SetSubject(agentID)` → the engine's canonical device pseudonym.
- `Process` stamps Subject (and observed_at) on events lacking them, then `ValidateEvent`s and rejects
  an invalid one.
- Wire the endpoint binary. Prove the stamped subject equals `pseudonym.Of(agentID)` and passes validation.

**Non-Goals**
- Live `xdr.Store.Resolve` at ingest (XDR-2 normalization).
- Changing the connectors (they stay low-level; the engine attributes).
- Full contract enforcement for non-endpoint paths (the gateway already stamps its subject, D87).

## Decisions

### D1 — The engine attributes; the connectors stay dumb
A fanotify parser knows a file path, not the device's canonical identity — and must never grow a
dependency on identity. So the ENGINE, which holds the device identity, stamps the subject. The
connectors keep producing target-only events; attribution is a single choke point (the engine) rather
than smeared across every connector, and the canonical derivation lives in exactly one place.

### D2 — Stamp only what is missing, then validate
`Process` stamps `Subject` from the configured pseudonym only if the event has none (a network event
that already carries a subject, D87, is untouched), and `observed_at` from the engine clock only if
unset. Then it runs `ValidateEvent` and returns the error on failure — so an event that is STILL invalid
after stamping (e.g. no target) is rejected loudly, closing the never-called-validator gap.

### D3 — Gated on a configured subject (backward-compatible)
Stamping + validation run only when `SetSubject` has been called. An engine with no configured device
identity behaves exactly as before (the existing tests, which don't configure one, are unchanged). In
production the endpoint binary always configures it from the enrolled agent identity, so real endpoint
events are always attributed and validated. The gate is honest: an engine that does not know its device
cannot attribute, and pretending otherwise (a fake subject) would be worse.

### D4 — The stamped subject is the canonical pseudonym, so it joins in XDR-1
`SetSubject(agentID)` stores `pseudonym.Of(agentID)` — the ONE derivation the gateway, posture, and the
entity model all use. So an endpoint event's stamped subject and a gateway request's subject for the
same device are the same string, and `xdr.Store.Resolve` coalesces them to one entity. This is why XDR-3
is on the XDR spine: it is what makes endpoint detections resolvable to the device entity.

## Risks / Trade-offs

- **Gated stamping means an unconfigured engine doesn't validate** — a test/degenerate case; production
  always configures the subject. Accepted, and the alternative (a fabricated default subject) is worse.
- **observed_at stamped at ingest, not at the kernel event** — a small skew between the real event time
  and when the engine sees it; acceptable for attribution, and the connectors can carry a real timestamp
  later (noted).

## Migration Plan

Additive: a setter + stamping/validation in `Process` (gated), and one binary wiring line. No proto,
core-contract, or connector change. Existing behavior is preserved unless a subject is configured.

## Open Questions

- Whether the connectors should eventually carry a real `observed_at` from the kernel event (vs the
  engine clock). Deferred; the engine clock is close enough for attribution.
