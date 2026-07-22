# dns-connector delta

## ADDED Requirements

### Requirement: The DNS connector runs a UDP listener that survives malformed input
The DNS connector MUST provide a UDP listener that binds a configurable address, parses each
received datagram into a query, and delivers it to a sink. A datagram that fails to parse MUST
be dropped and counted, never stopping the receive loop, and the drop count MUST be observable.
The listener MUST shut down cleanly on context cancellation and MUST refuse a nil sink.

#### Scenario: Valid queries are delivered and garbage is dropped
- **WHEN** the listener receives valid and malformed DNS datagrams
- **THEN** the valid queries are parsed and delivered, the malformed one is dropped and counted, monitoring keeps running, and the listener stops cleanly when cancelled
