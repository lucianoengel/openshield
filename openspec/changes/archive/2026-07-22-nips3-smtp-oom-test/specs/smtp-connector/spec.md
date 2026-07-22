## MODIFIED Requirements

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
