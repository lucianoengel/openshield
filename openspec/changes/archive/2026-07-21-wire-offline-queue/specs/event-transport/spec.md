# event-transport delta

## ADDED Requirements

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
