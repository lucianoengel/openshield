# syslog-connector delta

## ADDED Requirements

### Requirement: The syslog connector runs a UDP listener that survives malformed input
The syslog connector MUST provide a UDP listener that binds a configurable address, parses
each received datagram, and delivers the parsed message to a sink. A datagram that fails to
parse MUST be dropped and counted, never stopping the receive loop, and the drop count MUST
be observable. The listener MUST shut down cleanly on context cancellation, and MUST refuse
a nil sink.

#### Scenario: Valid datagrams are delivered and garbage is dropped
- **WHEN** the listener receives valid and malformed syslog datagrams
- **THEN** the valid ones are parsed and delivered, the malformed one is dropped and counted, ingest keeps running, and the listener stops cleanly when cancelled
