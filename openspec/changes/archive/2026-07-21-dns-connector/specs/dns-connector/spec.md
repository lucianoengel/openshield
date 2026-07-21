# dns-connector delta

## ADDED Requirements

### Requirement: The DNS connector parses a query into a metadata-only event and rejects malformed messages
The connector MUST decode the question of a DNS query into the queried name and type, bounded against a malformed or oversized message, and MUST reject a message that is too short, is a response rather than a query, has a truncated or over-length name, or contains a compression pointer in the question — never returning a partial or empty name as valid. It MUST produce a network event carrying the queried name as metadata only, never body content. It MUST provide a heuristic that scores a query name for DNS tunneling, rating a long high-entropy name high and an ordinary name low.

#### Scenario: A valid query produces an event and a malformed one is rejected
- **WHEN** the connector parses a DNS query message
- **THEN** a valid query yields the queried name in a DNS network event, a malformed or response message is rejected, and a long high-entropy name scores high on the tunneling heuristic while an ordinary name scores low
