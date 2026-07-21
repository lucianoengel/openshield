## Why

SEC-4 (P0). The control plane's NATS subscribers did a synchronous DB insert per message
with NO `SetPendingLimits` and NO `ErrorHandler`. A slow consumer overflows the client
buffer and drops messages SILENTLY and uncounted — violating the project's own "no silent
loss" invariant on the RECEIVE side (the send side has spool + gap detection; the receive
side had nothing).

## What Changes

- `Server.natsErrorHandler` — an async NATS ErrorHandler that counts (`DroppedMessages`) and
  loudly logs a drop (SlowConsumer above all), installed via `nats.ErrorHandler` at connect.
- `subscribeCounted` — every subscription gets explicit `SetPendingLimits`, so overflow is
  deterministic and fires the handler rather than relying on library defaults.

## Capabilities

### Modified Capabilities
- `control-plane`: receive-side message drops are counted and surfaced, never silent.

## Impact

- `internal/controlplane/controlplane.go`; `docs/decisions.md` D116.
- Proven: a flooded slow consumer (a blocking handler + a 1-message pending limit) fires the
  ErrorHandler — drops are OBSERVED, not a silent zero; and the server's handler increments
  `DroppedMessages` for every async error. Guards mutation-tested: **"swallow the error
  handler" (don't count) fails the test**.
- NOT in scope (stated): moving ingest to JetStream durable consumers with ack (PLAT-2 —
  which removes the drop window entirely rather than just observing it; this is the
  pending-limits/ErrorHandler stopgap the doc asks for now regardless); backpressure
  signalling to agents. This makes the drop OBSERVABLE (the invariant); durability is PLAT-2.
