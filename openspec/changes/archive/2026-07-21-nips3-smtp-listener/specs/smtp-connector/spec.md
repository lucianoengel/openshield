# smtp-connector delta

## ADDED Requirements

### Requirement: The SMTP connector runs a capture server that parses live sessions
The SMTP connector MUST provide a listener that accepts a TCP SMTP session, answers the
dialogue enough for a client to deliver a message, captures the transcript, parses it, and
delivers the message to a sink. A session that fails to parse MUST be dropped and counted,
never delivered as a partial message, and the drop count MUST be observable. The listener MUST
shut down cleanly on context cancellation and MUST refuse a nil sink.

#### Scenario: A real session is captured and a malformed one is dropped
- **WHEN** a client completes an SMTP session, and separately a malformed session occurs
- **THEN** the completed message is parsed and delivered to the sink, and the malformed session is dropped and counted
