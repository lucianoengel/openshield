## Why

The event contract requires a top-level pseudonymous `Subject` (`ValidateEvent`, `validate.go:103`) — but
the endpoint connectors (fanotify, filewatch, execaudit) set only the *target* (the file path, the
process), never the subject, and `ValidateEvent` is defined but **called nowhere**. So endpoint events
flow unattributed and unvalidated: a recurring "the contract says X but nothing enforces X" gap, and the
reason XDR-1's entity graph has nothing to resolve endpoint events by. XDR-3 closes it: the engine stamps
the device's **canonical pseudonym** as the event's Subject, so every endpoint detection carries the same
device identity the gateway and posture use — and it passes the contract validation that was never run.

## What Changes

- The engine is told its device's canonical pseudonym (`pseudonym.Of(agentID)`), and stamps it as
  `Event.Subject` on any event lacking one, plus `observed_at` if missing — so endpoint events satisfy
  the event contract.
- The engine then runs `ValidateEvent` and rejects an event that is still invalid — loudly, never
  silently processing a malformed one (closing the "defined-but-never-called" gap).
- The endpoint binary wires the engine's subject from its enrolled agent identity, so real fanotify /
  execaudit events carry the enrolled device pseudonym.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `endpoint-engine`: stamps the canonical device pseudonym (and observed_at) on endpoint events and
  enforces the event contract, so every endpoint detection is attributed to the device entity and
  validated.

## Impact

- **Code:** `Engine.SetSubject` + subject/observed_at stamping and `ValidateEvent` enforcement in
  `Process`; `cmd/openshield-engine` wires it from the agent identity. Gated on a configured subject, so
  the existing engine tests (which don't configure one) are unchanged. Proven: with a configured device,
  a connector-style event (no subject, no observed_at) is stamped with the canonical pseudonym and
  passes validation; the SAME device's stamped subject equals `pseudonym.Of(agentID)`, so it resolves to
  the XDR entity (D195); a still-invalid event (no target) is rejected.
- **Scope note (honest):** this stamps the DEVICE subject on endpoint events and enforces the contract in
  the engine. Cross-domain alert normalization into one table (XDR-2) and correlation (XDR-4) are the
  next spine steps. The gateway already stamps its subject (D87); wiring the engine's stamped subject
  into a live `xdr.Store.Resolve` at ingest is part of XDR-2's normalization.
