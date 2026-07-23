# dns-sinkhole Specification

## Purpose
The preventive DNS resolver (NIPS-8): it turns DNS from a passive tap into an inline control. It reads
UDP queries, SINKHOLES a policy/IOC-blocked domain (answers NXDOMAIN so the client cannot resolve the
malicious name — RPZ-style), and FORWARDS every other query to a configured upstream, relaying the
response. It FAILS OPEN — a query it cannot parse or classify is forwarded, never dropped or NXDOMAIN'd —
because a resolver that blackholes on uncertainty would break name resolution for the whole fleet. A
local cache, upstream failover, the transparent :53 redirect, a sinkhole-IP walled garden, and TCP/DoT
are follow-ups.

## Requirements
### Requirement: A DNS resolver sinkholes a blocked domain and forwards the rest

The system SHALL provide a DNS resolver that reads a UDP query, and for a domain on the blocked set — or a
subdomain of one — SHALL answer with an NXDOMAIN response built from the query (same transaction id and
question, no answers), so the client cannot resolve the malicious name; for any other domain it SHALL
forward the query to a configured upstream resolver and relay the response unchanged. A sinkholed query
MUST NOT be forwarded to the upstream.

#### Scenario: A blocked domain is sinkholed
- **WHEN** a query for a blocked domain (or a subdomain of one) is received
- **THEN** the resolver answers NXDOMAIN and does not forward the query upstream

#### Scenario: A normal query is forwarded and relayed
- **WHEN** a query for a domain that is not blocked is received
- **THEN** the resolver forwards it to the upstream and relays the upstream's response to the client

### Requirement: The resolver fails open — it never blackholes name resolution

The resolver MUST fail open: a message it cannot parse as a query, or a domain the block set does not
match, MUST be forwarded to the upstream rather than dropped or answered NXDOMAIN. A classification gap or
a malformed input MUST NEVER cause the resolver to refuse a name it is not certain is blocked, because a
resolver that blackholes on uncertainty would break name resolution for the whole fleet.

#### Scenario: An unparseable query is forwarded, not dropped
- **WHEN** a message that cannot be parsed as a DNS query is received
- **THEN** it is forwarded to the upstream (fail-open), not dropped or sinkholed

#### Scenario: An unmatched domain is forwarded
- **WHEN** a query's domain is not on the blocked set
- **THEN** it is forwarded to the upstream and resolved normally
