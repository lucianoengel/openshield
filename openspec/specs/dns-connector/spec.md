# dns-connector Specification

## Purpose
A DNS-query connector that parses a DNS question off the wire into a metadata-only network Event, so DNS resolution enters the same pipeline as file and HTTP events, and scores query names for DNS-tunneling / exfiltration. It is a pure parser and Event producer; the socket listener and transparent redirect are a separate, privileged data-plane concern.

## Requirements

### Requirement: The DNS connector parses a query into a metadata-only event and rejects malformed messages
The connector MUST decode the question of a DNS query into the queried name and type, bounded against a malformed or oversized message, and MUST reject a message that is too short, is a response rather than a query, has a truncated or over-length name, or contains a compression pointer in the question — never returning a partial or empty name as valid. It MUST produce a network event carrying the queried name as metadata only, never body content. It MUST provide a heuristic that scores a query name for DNS tunneling, rating a long high-entropy name high and an ordinary name low.

#### Scenario: A valid query produces an event and a malformed one is rejected
- **WHEN** the connector parses a DNS query message
- **THEN** a valid query yields the queried name in a DNS network event, a malformed or response message is rejected, and a long high-entropy name scores high on the tunneling heuristic while an ordinary name scores low

### Requirement: The DNS connector runs a UDP listener that survives malformed input
The DNS connector MUST provide a UDP listener that binds a configurable address, parses each
received datagram into a query, and delivers it — together with the datagram's source IP — to a
sink. The source IP is load-bearing: an Event produced from a query carries it as the flow's
origin, and a network decision that cannot say who asked is not actionable. A datagram that
fails to parse MUST be dropped and counted, never stopping the receive loop, and the drop count
MUST be observable. The listener MUST shut down cleanly on context cancellation and MUST refuse
a nil sink.

#### Scenario: Valid queries are delivered with their source and garbage is dropped
- **WHEN** the listener receives valid and malformed DNS datagrams
- **THEN** the valid queries are parsed and delivered to the sink with the sender's source IP, the malformed one is dropped and counted, monitoring keeps running, and the listener stops cleanly when cancelled

### Requirement: The DNS listener bounds its admission rate
The DNS listener MUST bound the rate at which it admits datagrams into the pipeline with a global
rate limit, so a datagram beyond the sustained rate is dropped before it produces a pipeline event —
a spoofed-source query flood cannot grow the audit ledger at wire speed. The rate-limit drops MUST be
counted separately from parse drops, so a flood is observable.

#### Scenario: A flood beyond the rate is dropped before minting events
- **WHEN** the listener receives far more datagrams than its admission rate allows
- **THEN** only the datagrams within the burst/rate are delivered to the sink and the excess are dropped and counted as rate-limited
