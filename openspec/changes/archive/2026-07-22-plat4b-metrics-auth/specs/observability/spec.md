# observability (delta)

## ADDED Requirements

### Requirement: The metrics endpoint can require auth and warns on exposure
The metrics endpoint MUST support requiring a bearer token, rejecting a request without the exact
token (compared in constant time) with 401, because its counters leak operational tempo useful for
reconnaissance. When the endpoint is bound to an address reachable beyond loopback without a token
configured, the server MUST warn loudly at startup rather than exposing it silently.

#### Scenario: An unauthenticated request is refused and an exposed bind is flagged
- **WHEN** the metrics endpoint is configured with a token and receives a request without it, and separately is bound to a non-loopback address without a token
- **THEN** the tokenless request is refused with 401 while the correct token is served, and the exposed bind produces a loud startup warning
