## MODIFIED Requirements

### Requirement: The transport documents its actual delivery guarantee

The transport's own documentation MUST describe what the code actually does in each mode and MUST NOT
claim a guarantee the code does not provide. In the DEFAULT mode it is durable JetStream delivery with
at-least-once, explicit-acknowledgement semantics, and the documentation MUST say so. In the OPTED-OUT
mode it is core NATS, at-most-once, and the documentation MUST say that and name the offline spool as the
outage-durability mechanism. In both modes the documentation MUST state that the stream is a delivery bus,
NOT the system-of-record (the hash-chained ledger is; D12), so stream retention is never treated as
evidence.

The documentation MUST NOT describe durable ingest as loss-free: a message never published and never
spooled is lost, and the stream's bounded limits mean a long enough consumer outage still drops.

#### Scenario: The transport doc matches the code in each mode
- **WHEN** the transport package documentation is read
- **THEN** it states durable at-least-once JetStream for the default mode, core NATS / at-most-once for the
  opted-out mode, points to the offline queue as the pre-broker durability, never claims the stream is the
  evidence store, and never claims loss-freedom

### Requirement: Signed telemetry can be delivered durably with explicit acknowledgement

Durable delivery SHALL be the DEFAULT: with no configuration, the transport MUST publish signed telemetry
into a persistent JetStream stream (surviving a broker or consumer restart) and MUST deliver it to the
control plane through a durable, explicit-acknowledgement consumer, so a message is retained until the
control plane has acknowledged it. A publish that the broker does not accept MUST fall back to the same
offline spool as the opted-out mode (no loss before the broker), and the stream MUST be a delivery bus with
retention bounded by acknowledgement — never the evidence store (D12).

An explicit opt-out MUST remain available for a deployment whose broker has no JetStream.

#### Scenario: Telemetry published while the consumer is down is delivered after it returns
- **WHEN** several signed messages are published with NO configuration override while the control-plane
  consumer is not running, and the consumer then starts
- **THEN** every published message is delivered to the consumer (none lost — the exact case at-most-once
  core NATS loses), and each is acknowledged only after the control plane has handled it
- **AND** the test FAILS if the default reverts to opt-in

## ADDED Requirements

### Requirement: Every real producer publishes into the durable stream, not only the simulator

The system SHALL ensure every process that publishes signed telemetry — the endpoint engine, the network
gateway, and the fleet simulator — switches its publisher to the durable path in the default mode. A producer that builds a
signed publisher and leaves it on core NATS makes the durability claim false for whatever it observes,
which is worse than an honest at-most-once mode because the claim is still being made elsewhere.

This SHALL be verified by a test at the publisher seam, not by inspecting the binaries' startup code, so
the omission cannot silently return.

#### Scenario: A producer's publisher is on the durable path by default
- **WHEN** a signed publisher is constructed the way a real producer constructs it, with no configuration
  override
- **THEN** it publishes into the JetStream stream, and a consumer reading the stream receives the message
- **AND** the test FAILS if a producer's durable-path switch is removed

### Requirement: An unavailable JetStream is a startup failure, not a silent downgrade

The system SHALL fail to start, with an error naming the opt-out, when durable ingest is in effect and
JetStream is unavailable (the broker does not support it, or the telemetry stream cannot be ensured). It
SHALL NOT fall back to core NATS.

A silent fallback would reintroduce at-most-once telemetry in a deployment that believes it is durable,
which is the missing-evidence failure this capability exists to prevent; loud refusal is the only outcome
that keeps the delivery guarantee honest.

#### Scenario: A broker without JetStream refuses to start the producer
- **WHEN** a producer starts against a broker with no JetStream support and no opt-out is configured
- **THEN** startup fails with an error naming the opt-out environment variable
- **AND** the test FAILS if the implementation degrades to core NATS instead

#### Scenario: The opt-out uses core NATS
- **WHEN** the opt-out is configured
- **THEN** the transport uses core NATS and does not require JetStream on the broker
