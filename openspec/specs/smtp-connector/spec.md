# smtp-connector Specification

## Purpose
An SMTP-message connector that parses an outbound SMTP session into its envelope (sender, recipients) and message body, so email enters the same pipeline as file, HTTP, and DNS events. The body is classified for PII/secrets in the sandboxed worker; the recipient domain is metadata for egress policy. It is a pure parser and Event producer; the port 25/587 listener and MTA interception are a separate, privileged data-plane concern.

## Requirements

### Requirement: The SMTP connector parses a session into an envelope and a classifiable body
The connector MUST parse an SMTP client transcript into the envelope sender and recipients
and the DATA message body, applying dot-unstuffing and ending the body at the lone-dot
terminator, and MUST reject a session with no sender, no recipient, or an unterminated DATA
block — never returning a partial message as complete. The message body MUST be available
for classification but MUST NOT be placed in the event; the event MUST carry only envelope
metadata (the recipient domain), never a full recipient address or the body.

#### Scenario: A session yields a classifiable body and domain-only metadata
- **WHEN** the connector parses an SMTP session carrying sensitive content
- **THEN** the body is extracted (dot-unstuffed, terminator-bounded) and its PII is detected by the classifier, the event carries the recipient domain but not the full address or body, and a malformed session is rejected

### Requirement: The SMTP connector runs a capture server that parses live sessions
The SMTP connector MUST provide a listener that accepts a TCP SMTP session, answers the
dialogue enough for a client to deliver a message, captures the transcript, parses it, and
delivers the message to a sink. A session that fails to parse MUST be dropped and counted,
never delivered as a partial message, and the drop count MUST be observable. The listener MUST
shut down cleanly on context cancellation and MUST refuse a nil sink.

The listener MUST bound the resources any single connection and the connection set as a whole can
consume, because it accepts attacker-controlled input: the bytes buffered for one session MUST be
bounded by a per-session size ceiling (an unterminated/no-newline stream must not grow memory without
limit), a session that stalls between lines MUST be timed out and dropped (no slowloris hold), and the
number of concurrent sessions MUST be capped, with connections beyond the cap refused and counted
rather than queued. The per-session size ceiling MUST be independently configurable (tunable to an
aggressive bound, defaulting when non-positive, never disablable), and MUST bound a no-newline stream
ON ITS OWN — even when the idle timeout would not fire.

#### Scenario: A real session is captured and a malformed one is dropped
- **WHEN** a client completes an SMTP session, and separately a malformed session occurs
- **THEN** the completed message is parsed and delivered to the sink, and the malformed session is dropped and counted

#### Scenario: Resource-exhaustion attempts are bounded
- **WHEN** a connection sends a stream with no newline, a connection stalls after the greeting, or more connections are opened than the concurrency cap
- **THEN** the no-newline session is bounded and dropped, the stalled connection is timed out, and the excess connections are refused and counted

#### Scenario: The size ceiling bounds a no-newline flood without the idle timeout
- **WHEN** a connection streams more than the configured per-session size ceiling with no newline and without stalling, under a large idle timeout
- **THEN** the session is bounded and dropped by the size ceiling before the idle timeout fires — so the size bound holds on its own, not only via the slowloris timeout

### Requirement: The SMTP capture listener MUST be startable by configuration

A shipped binary MUST bind the SMTP capture listener when an operator configures a listen address,
and MUST feed each parsed message into the same event pipeline as file, DNS and process events.

A connector that cannot be started by any configuration is not a capability of the product,
regardless of how completely it is implemented or tested.

#### Scenario: A configured listener ingests a live session

- **WHEN** an operator configures an SMTP listen address and a client delivers a message to it
- **THEN** the message MUST enter the pipeline and produce an audit entry

#### Scenario: No configuration leaves the listener inert

- **WHEN** no SMTP listen address is configured
- **THEN** no listener is bound, and the rest of the engine runs unchanged

### Requirement: An email body MUST be classified like any other content

The body of a captured message MUST be classified by the same content path as a file, and a
checksum-backed detection in an email body MUST reach a decision.

#### Scenario: A message carrying sensitive content alerts

- **WHEN** a captured message's body contains a checksum-valid identifier
- **THEN** the decision MUST be an alert, and an audit entry MUST be recorded

#### Scenario: The message body does not reach the ledger

- **WHEN** a message carrying sensitive content is decided upon
- **THEN** no audit entry may contain the body's sensitive value

### Requirement: The listener MUST state its limits when it starts

On binding, the connector MUST report that it is a capture listener rather than a mail transfer
agent, that it does not handle TLS-negotiated sessions, and that it is observe-only.

An operator who points production mail at a capture listener, or who expects a STARTTLS client to be
inspected, is wrong in a way that only surfaces later — as undelivered mail, or as a channel that
silently inspects nothing.

#### Scenario: Enabling the listener announces what it is not

- **WHEN** the SMTP listener binds
- **THEN** its startup output MUST state that it is not an MTA and does not handle TLS
<!-- synced from smtp-connector-wiring -->
