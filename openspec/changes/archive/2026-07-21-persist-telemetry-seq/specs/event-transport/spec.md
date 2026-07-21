# event-transport delta

## ADDED Requirements

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
