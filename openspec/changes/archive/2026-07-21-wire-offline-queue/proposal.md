## Why

Audit finding #4 (part 2), verified: the durable offline queue (D40, T-024) is
built and tested but has ZERO production callers — `cmd/openshield-fleet-agent`
publishes directly and discards errors (`_ = pub.Publish…`). So the "offline-
capable" core principle (D1) is unrealized: a laptop that wakes on a train with
the control plane unreachable loses every signed telemetry message it produces —
the exact silent loss the whole system exists to prevent. Core NATS is
fire-and-forget (D66): a publish while the subscriber is down succeeds with
nothing stored.

## What Changes

- `SignedPublisher` gains an optional durable SPOOL: when the control plane is
  unreachable (or the spool is non-empty), the SIGNED envelope bytes are stored
  and re-published verbatim on `Flush` — sequence and signature are baked in, so
  a late message verifies exactly as a live one (a gap at worst, D50). FIFO order
  is preserved (a new message goes behind anything queued).
- `cmd/openshield-fleet-agent` opens a bounded `queue.Queue` at
  `OPENSHIELD_QUEUE_DIR`, attaches it, and `Flush`es on each tick; an overflow
  eviction fires a LOUD log (the honest guarantee is "no SILENT loss", not "no
  loss", D31).
- Store-or-forward logic is behind injectable seams (send/connected) so it is
  testable without a live broker.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `event-transport`: the signed publisher durably spools telemetry when the
  control plane is unreachable and re-sends it on reconnect, so an outage causes a
  gap and a delay, not silent loss.
- `offline-queue`: the durable spool is now WIRED into the running fleet agent —
  the D40 mechanism has a production caller.

## Impact

- New: a `Spool` seam + store-or-forward + `Flush` on `SignedPublisher`; fleet-
  agent wiring (`OPENSHIELD_QUEUE_DIR`, periodic flush, loud overflow); tests.
  Docs (D67).
- Honest bound (D31): the queue is BOUNDED — overflow drops the OLDEST record and
  fires a loud callback; the guarantee is no SILENT loss, not no loss. Late
  delivery creates gaps (accepted, D50). Respects D1 (offline-capable), D50, D66.
