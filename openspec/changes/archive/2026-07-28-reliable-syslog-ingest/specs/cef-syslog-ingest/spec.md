## ADDED Requirements

### Requirement: External log ingest offers a transport that does not lose events silently

The system SHALL accept estate logs over a STREAM transport in addition to datagrams, so that a receiver
which cannot keep up applies backpressure to its senders rather than discarding events.

Datagram ingest SHALL remain available for devices that cannot do better, and SHALL be documented as
best-effort and NOT evidentiary. Its loss is invisible by construction: a datagram the kernel discards
for want of buffer never reaches the application, so no counter the application keeps can observe it.

The stream transport SHALL accept both framings that real senders emit — octet-counted and
newline-terminated — because requiring one of them is how a log source ends up not onboarded.

**Honest limit, which SHALL be stated wherever the guarantee is described:** a stream transport removes
kernel-level silent drop and adds backpressure. It does NOT acknowledge PERSISTENCE, so a receiver killed
with buffered data still loses it. The claim is that loss requires a crash or an explicit refusal — both
observable — rather than a buffer quietly filling.

#### Scenario: A stream-delivered event is stored
- **WHEN** a sender delivers a CEF event over the stream transport
- **THEN** it is parsed and stored as a searchable external log

#### Scenario: Both framings are accepted
- **WHEN** senders deliver messages using octet-counted framing and newline-terminated framing
- **THEN** both are ingested

#### Scenario: An oversized message is refused and counted, never truncated
- **WHEN** a sender delivers a message longer than the configured bound
- **THEN** the message is refused and counted, and no partial event is stored

#### Scenario: A malformed message does not end the stream
- **WHEN** a sender delivers an unparseable message followed by a valid one
- **THEN** the unparseable message is counted, the valid one is stored, and the connection stays open

### Requirement: Evidentiary ingest authenticates the sender

The system SHALL offer external-log ingest over TLS with MUTUAL authentication, refusing at the handshake
any sender that does not present a certificate issued by the operator's authority.

Without it, anything able to reach the port can inject events into a store the product invites operators
to treat as evidence — and fabricated evidence is a worse failure than lost evidence. Transport
encryption alone does not address this: it protects a message in flight while leaving the sender
anonymous.

#### Scenario: A sender with an operator-issued certificate is accepted
- **WHEN** a sender presents a certificate issued by the configured authority
- **THEN** the connection is accepted and its messages are ingested

#### Scenario: A sender without a certificate is refused at the handshake
- **WHEN** a sender connects presenting no client certificate
- **THEN** the handshake fails and no message from it is stored

#### Scenario: A sender with an untrusted certificate is refused
- **WHEN** a sender presents a well-formed certificate from an authority the deployment does not trust
- **THEN** the handshake fails and no message from it is stored
