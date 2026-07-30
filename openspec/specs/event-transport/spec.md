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


### Requirement: Network telemetry redacts the user IP and URL path before crossing the boundary
A network Event projected as telemetry MUST have its user-identifying and content-like fields removed
before it crosses to the control plane: the source IP and port (the Event already carries a
pseudonymous subject) and the HTTP path (which can carry tokens, credentials, or search terms). The
destination host/address, method, protocol, direction, and flow id MAY be retained so the fleet view
knows the destination and can correlate the verdict.

#### Scenario: The redacted network telemetry keeps destination, drops user IP and path
- **WHEN** a network Event is redacted for telemetry
- **THEN** its source IP/port and HTTP path are empty and its destination and method are retained

### Requirement: Real endpoint detections reach the verified telemetry stream
The endpoint engine MUST be able to publish its real detections (Event + Decision) to the control plane
through the signed transport, so fleet visibility, peer analytics, and the dead-man's-switch operate
over real endpoint detections rather than only a simulator. Publishing MUST be signed by an enrolled
identity and MUST be opt-in (enabled only when transport and enrollment are configured).

#### Scenario: An enrolled engine publishes a real detection
- **WHEN** an engine configured with transport and an enrolled identity produces a detection
- **THEN** the signed Event and Decision are published to the control plane's verified stream

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

### Requirement: A long-lived process MUST retry its broker connection forever

Every long-lived OpenShield process SHALL reconnect to the broker without a retry ceiling, with jitter,
and SHALL report losing and regaining the connection.

nats.go defaults to 60 attempts at 2s — a budget of roughly two minutes, after which the client closes
permanently and the process never publishes or receives again while continuing to run. No process passed
any reconnect option, so all of them inherited it. Two minutes is not a long outage: a laptop closed over
lunch, a switch reboot, a VPN drop, a broker upgrade.

The consequence differs by process and none of them is acceptable:

- The AGENT keeps producing into the durable spool that exists so an outage causes a gap rather than
  silent loss, and can now never drain it — so the spool fills to its ceiling and begins DROPPING THE
  OLDEST records. A bounded outage silently becomes unbounded evidence loss.
- The CONTROL PLANE stops consuming, which is the whole fleet's ingest rather than one endpoint.
- The ENGINE and GATEWAY stop publishing decisions, so enforcement continues and the record of it does not.

Jitter is required, not cosmetic: a fleet waiting on one fixed interval reconnects in lockstep and
stampedes the broker that just came back.

A SHORT-LIVED command MUST NOT use this policy. An operator subcommand that publishes one message and
exits should fail promptly; retrying forever would hang a CLI.

#### Scenario: An outage longer than the default retry budget still recovers
- **WHEN** the broker is unavailable for longer than the client's default reconnect budget and then returns
- **THEN** the process reconnects and the records held during the outage are delivered and stored

#### Scenario: A retry ceiling is caught
- **WHEN** a finite reconnect ceiling is configured
- **THEN** the scenario fails because the spool never drains

#### Scenario: Losing the broker is reported when it happens
- **WHEN** the broker connection drops
- **THEN** the process says so, rather than leaving it to be inferred from missing data later

#### Scenario: A clean shutdown raises no alarm
- **WHEN** a process closes its broker connection deliberately during shutdown
- **THEN** no permanent-failure warning is emitted, because a maximum-severity line on every normal exit
  is one operators learn to ignore
