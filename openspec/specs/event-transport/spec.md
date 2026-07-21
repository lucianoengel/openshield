# Event Transport

## Purpose

The agent↔control-plane boundary. Carries only wire forms, fails explicitly rather than silently, and is shaped so a durable store-and-forward implementation can substitute later — a seam, not yet a guarantee.

> Synced from change `add-pipeline-dispatcher` on 2026-07-20.
> Implemented in `internal/core` and `internal/transport/nats`; invariants
> mutation-tested (see the change's tasks.md).
## Requirements
### Requirement: Transport carries only the wire forms
The transport SHALL accept `Event`, `ClassificationSummary` and `Decision`. It SHALL have no
method accepting `LocalClassification`.

The two-type split in the classification contract is only worth anything if the transport
enforces it. A redaction step at the boundary would be a runtime behaviour; a missing method is
a compile error.

#### Scenario: The local form cannot be transmitted
- **WHEN** code attempts to publish a `LocalClassification`
- **THEN** compilation fails
- **AND** this is asserted by the same negative-compile mechanism used for enforcer isolation,
  checking the specific compiler error rather than merely a failed build

### Requirement: Delivery failure is explicit, never silent
When the control plane is unreachable the transport SHALL return an explicit error naming the
condition. It SHALL NOT discard the payload, and it SHALL NOT block the pipeline.

The pipeline runs while a process may be blocked in the kernel. A transport that blocks on a
network write moves a network problem into the syscall path — the exact failure mode this
architecture exists to avoid.

#### Scenario: Unreachable control plane does not stall the pipeline
- **WHEN** the control plane is unreachable and a Decision is published
- **THEN** the call returns an error within its deadline
- **AND** the pipeline continues
- **AND** a test asserts the publish call returns faster than the pipeline stage deadline

#### Scenario: Dropping is a decision, not an accident
- **WHEN** the transport cannot deliver and no durable queue is configured
- **THEN** it returns an error the caller must handle
- **AND** no code path discards a payload without returning an error

### Requirement: The durable-queue seam exists without being implemented
The transport interface SHALL be shaped so that a store-and-forward implementation can be
substituted without changing callers. This change SHALL NOT claim offline capability.

"Offline-capable" is a stated project principle and it is **not delivered here** — that is T-024.
Recording the gap explicitly prevents the interface from being mistaken for the guarantee.

#### Scenario: An alternative implementation substitutes cleanly
- **WHEN** a test double implementing the transport interface is substituted
- **THEN** callers compile and behave unchanged
- **AND** no caller references a NATS type

### Requirement: Replay reproduces the recorded Decision
Replay of a recorded Event through the pipeline configuration that produced a Decision MUST
yield an equal Decision, comparing an explicit field list that excludes non-deterministic
fields.

Replay is what makes the audit trail an investigation tool rather than a log. If a recorded
decision cannot be reproduced, "every decision should be explainable" is unfounded.

#### Scenario: A recorded Event replays to the same Decision
- **WHEN** an Event is dispatched, recorded, and later replayed through the same configuration
- **THEN** the replayed Decision equals the recorded one in action, confidence, reason and
  policy identity
- **AND** fields that legitimately differ (decision ID, timestamps) are excluded from the
  comparison by an explicit list, so that adding a new non-deterministic field fails the test
  rather than silently weakening it

### Requirement: The signed sequence survives a restart
The signed publisher MUST persist its telemetry sequence so that after a restart it resumes with a
sequence strictly greater than any it previously used — never reusing one — so a routine restart does
not emit sequences the control plane will reject as replays.

Persistence is reservation-based (a high-water mark persisted in blocks, atomically), bounding write
cost; a corrupt or unreadable sequence file MUST fail loudly rather than silently reset to zero. A
reserved-but-unused range after a crash appears as a gap, which is accepted and counted (D50), not a
replay.

#### Scenario: Sequence is monotonic across a restart
- **WHEN** a publisher emits some sequences, is discarded, and is recreated from the same sequence file
- **THEN** its next sequence is strictly greater than any it used before
- **AND** a test asserts no sequence is reused across the restart

### Requirement: The transport documents its actual delivery guarantee
The transport's own documentation MUST describe what the code does — core NATS, at-most-once — and MUST
NOT claim JetStream or durability the code does not provide; durability across a control-plane outage is
named as the offline queue's responsibility.

#### Scenario: The transport doc matches the code
- **WHEN** the transport package documentation is read
- **THEN** it states core NATS / at-most-once and does not claim JetStream
- **AND** it points to the offline queue as the durability mechanism

### Requirement: Signed telemetry is durably spooled during an outage
The signed publisher MUST, when a durable spool is attached, store signed telemetry that cannot be
sent because the control plane is unreachable, and re-send it in order on a later flush — so a
control-plane outage causes a delay and a gap, not silent loss (D1/D31).

Re-sent messages carry their original sequence and signature (the raw envelope is stored), so a late
message verifies exactly as a live one. FIFO order is preserved: while anything is spooled, a new
message is enqueued behind it rather than racing ahead on a recovered connection.

#### Scenario: Telemetry produced during an outage is spooled and later delivered in order
- **WHEN** the control plane is unreachable and the agent produces several signed messages, then the
  connection recovers and the publisher flushes
- **THEN** the messages were durably queued (none lost) and are delivered in the order produced,
  byte-for-byte (sequence and signature intact)
- **AND** a test drives an outage, asserts the messages are queued, then flushes and asserts in-order
  delivery of the exact bytes

