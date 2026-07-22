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

#### Scenario: A real session is captured and a malformed one is dropped
- **WHEN** a client completes an SMTP session, and separately a malformed session occurs
- **THEN** the completed message is parsed and delivered to the sink, and the malformed session is dropped and counted
