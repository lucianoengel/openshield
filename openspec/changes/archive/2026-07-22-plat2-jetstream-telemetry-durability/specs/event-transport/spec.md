## MODIFIED Requirements

### Requirement: The transport documents its actual delivery guarantee
The transport's own documentation MUST describe what the code actually does in each mode and MUST NOT
claim a guarantee the code does not provide. In the DEFAULT mode it is core NATS, at-most-once, and the
documentation MUST say so and name the offline spool as the outage-durability mechanism. In the durable
mode (when enabled) it delivers signed telemetry over a JetStream stream with at-least-once,
explicit-ack semantics, and the documentation MUST describe that — and MUST state that the stream is a
delivery bus, NOT the system-of-record (the hash-chained ledger is; D12), so stream retention is never
treated as evidence.

#### Scenario: The transport doc matches the code in each mode
- **WHEN** the transport package documentation is read
- **THEN** it states core NATS / at-most-once for the default mode and durable at-least-once JetStream for the enabled mode, points to the offline queue as the pre-broker durability, and never claims the stream is the evidence store

## ADDED Requirements

### Requirement: Signed telemetry can be delivered durably with explicit acknowledgement

When durable delivery is enabled, the transport MUST publish signed telemetry into a persistent
JetStream stream (surviving a broker or consumer restart) and MUST deliver it to the control plane
through a durable, explicit-acknowledgement consumer, so a message is retained until the control plane
has acknowledged it. A publish that the broker does not accept MUST fall back to the same offline spool
as the default mode (no loss before the broker), and the stream MUST be a delivery bus with
retention bounded by acknowledgement — never the evidence store (D12).

#### Scenario: Telemetry published while the consumer is down is delivered after it returns
- **WHEN** durable delivery is enabled, several signed messages are published while the control-plane consumer is not running, and the consumer then starts
- **THEN** every published message is delivered to the consumer (none lost — the exact case at-most-once core NATS loses), and each is acknowledged only after the control plane has handled it
