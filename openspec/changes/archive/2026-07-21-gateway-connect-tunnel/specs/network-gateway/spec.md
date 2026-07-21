# network-gateway delta

## ADDED Requirements

### Requirement: The proxy tunnels HTTPS via CONNECT without inspecting it
The proxy MUST handle the HTTP CONNECT method by establishing a blind TCP tunnel between the client and
the requested upstream — hijacking the client connection, dialing the upstream, acknowledging with 200,
and relaying bytes both directions until either side closes. Because the TLS session is end to end
between the client and the origin, the proxy MUST NOT attempt to classify tunneled bytes, and MUST log
each tunnel so the uninspected egress is operationally visible rather than silent. A failure to reach
the upstream MUST return 502.

#### Scenario: An HTTPS request transits the tunnel and is not classified
- **WHEN** an HTTPS client sends a request through the proxy via CONNECT and the upstream is reachable
- **THEN** the request succeeds end to end and its response is returned to the client
- **AND** nothing about the tunneled body is recorded to the audit ledger

#### Scenario: A tunnel to an unreachable upstream fails cleanly
- **WHEN** a CONNECT names an upstream that cannot be dialed
- **THEN** the proxy returns 502 rather than hanging or crashing
