# offline-queue Specification

## Purpose
The agent telemetry store-and-forward: a bounded, durable, FIFO disk queue wrapping any Transport, so an offline agent never silently drops a payload — held on disk, delivered in order on reconnect, and overflow drops oldest as a loud audit event (no silent loss, bounded guarantee).
## Requirements
### Requirement: An unreachable control plane never silently drops a payload
When the inner transport is unreachable, the queueing transport MUST persist the payload durably
and MUST NOT drop it silently. A payload accepted while offline MUST survive a process restart.

For a product whose only honest claim is a trail of what it saw, losing that trail on a network
blip is the failure the whole system exists to prevent (D1, D31). Held-on-disk is the difference
between "delivery is pending" and "the event never happened".

#### Scenario: Payloads produced while offline are delivered on reconnect, in order
- **WHEN** the control plane is unreachable, several payloads are published, then it returns and
  Flush runs
- **THEN** every payload is delivered, in the order it was produced
- **AND** a test drives offline→online and asserts completeness and FIFO order

#### Scenario: The queue survives a restart
- **WHEN** payloads are queued offline and the queue is reopened from the same directory
- **THEN** the queued payloads are still present and drain in order
- **AND** a test reopens the spool and asserts nothing was lost

#### Scenario: A torn write cannot corrupt the queue
- **WHEN** a payload file is written
- **THEN** it appears atomically (complete or absent), so a crash mid-write leaves no partial record
- **AND** the drain path skips or is never given a partial file

### Requirement: The queue is bounded and overflow is a loud event
The queue MUST have a maximum size and, on overflow, MUST drop the oldest payload and invoke an
overflow callback so the drop is recorded as a high-severity audit event. It MUST NOT grow without
limit and MUST NOT drop silently.

An unbounded spool is a disk-exhaustion DoS; a silent drop is indistinguishable from nothing
happening (D17). The honest guarantee is "no silent loss", not "no loss" — a bounded queue that
overflows has lost data, and that fact must be recorded, not hidden.

#### Scenario: Overflow drops oldest and fires the callback
- **WHEN** the queue is at its ceiling and another payload is enqueued
- **THEN** the oldest payload is dropped, the overflow callback is invoked, and the new payload is
  retained
- **AND** a test fills past the ceiling and asserts the drop, the callback, and that the newest
  payload survived

### Requirement: Callers use the same interface
The queueing transport MUST implement `core.Transport` so existing callers are unchanged, and a
payload published while the control plane is reachable and the queue empty MUST go directly without
touching disk.

The transport seam was shaped so a durable implementation substitutes without changing callers. If
using the queue meant a different interface, every call site would have to know about offline mode,
which is the coupling the seam exists to avoid.

#### Scenario: Online with an empty queue publishes directly
- **WHEN** the inner transport is reachable and the queue is empty
- **THEN** the payload is published directly and no file is written
- **AND** once anything is queued, subsequent payloads queue behind it to preserve order

### Requirement: The durable spool has a production caller
The durable offline queue MUST be wired into the running agent, so the offline-capable principle (D1)
is realized rather than only unit-tested. The agent flushes the spool as connectivity allows, and a
bounded-queue overflow eviction MUST be surfaced loudly (no silent loss, D31).

#### Scenario: The fleet agent spools and flushes, and overflow is loud
- **WHEN** the fleet agent runs with a queue directory configured and the control plane is intermittently
  unreachable
- **THEN** telemetry is spooled during the outage and flushed when reachable, and an overflow eviction
  fires a high-severity log
- **AND** a test asserts the wiring flushes and that overflow is reported, not silent

