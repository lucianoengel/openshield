# policy-evaluation delta

## ADDED Requirements

### Requirement: The policy can decide on the requested service for microsegmentation
The policy input MUST expose the requested service host, method, and path for a network event, so a
policy can make per-service (and per-endpoint) authorization decisions. Exposing these to the local
in-process policy MUST NOT change what crosses the host boundary — telemetry still redacts the URL path.

#### Scenario: A policy authorizes a role to a specific service
- **WHEN** a policy conditions on the event host and the identity role
- **THEN** it can allow a role to one service host and deny it another
