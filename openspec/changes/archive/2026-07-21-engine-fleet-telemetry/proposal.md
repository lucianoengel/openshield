## Why

The standout audit finding: `openshield-engine` — the only component producing REAL
endpoint detections — writes to its LOCAL ledger and never publishes telemetry. So
the control plane's verified stream has only ever carried the fleet-agent SIMULATOR's
synthetic events + gateway projections (D77) — **fleet visibility, peer-UEBA
(D53/D54), and the dead-man's-switch (D50/D51) have never operated over a single real
endpoint detection.** Both halves already exist (the gateway wires SignedPublisher +
the shared `enroll` helper); the engine just doesn't. This connects it.

## What Changes

- `internal/engine.Engine` gains an OPTIONAL telemetry `Projector` (narrow interface:
  PublishEvent + PublishDecision — the shape `gateway.Projector` uses, defined
  engine-local for clean layering) and a logger. `SetTelemetry(Projector)`. nil = no
  projection (the default, additive, never the system of record — the local
  forward-secure ledger stays authoritative, D30).
- In `Process`, after a Decision is recorded locally, if telemetry is configured,
  project the Event + Decision best-effort (a publish error is logged, never fails
  Process; the publisher offline-queues, D67). The Event's FilesystemSubject path is
  the FILE's identity (needed for fleet investigation) and the Subject is already
  pseudonymous (D23), so the Event is projected as-is — distinct from the gateway,
  which redacted the URL path (content-like). The Decision carries no content (D14).
- `cmd/openshield-engine`: when NATS + an enrollment endpoint are configured,
  generate an identity, enroll, build a SignedPublisher, and SetTelemetry — exactly
  as the gateway does; else projection stays off (the observe-only default unchanged).

## Capabilities

### Modified Capabilities
- `endpoint-engine`: the engine projects real detections (Event + Decision) to the
  control plane, opt-in and additive to the local ledger.
- `event-transport`: real endpoint detections reach the verified telemetry stream,
  not only the simulator.

## Impact

- `internal/engine` (telemetry field + projection), `cmd/openshield-engine` wiring,
  `docs/decisions.md` D80. Reuses `SignedPublisher`, `enroll`, and the D77 pattern.
- Proven with a fake Projector (no NATS): a file event Process projects one Event
  (path retained) + one Decision; nil projects nothing; a publish error does not fail
  Process.
- NOT in scope (stated): retiring the fleet-agent simulator (still useful for
  control-path e2e); path redaction (a configurable follow-up); ClassificationSummary
  projection. Respects D10/D29, D23, D30, D41/D44, D67.
