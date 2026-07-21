# event-transport delta

## ADDED Requirements

### Requirement: Network telemetry redacts the user IP and URL path before crossing the boundary
A network Event projected as telemetry MUST have its user-identifying and content-like fields removed
before it crosses to the control plane: the source IP and port (the Event already carries a
pseudonymous subject) and the HTTP path (which can carry tokens, credentials, or search terms). The
destination host/address, method, protocol, direction, and flow id MAY be retained so the fleet view
knows the destination and can correlate the verdict.

#### Scenario: The redacted network telemetry keeps destination, drops user IP and path
- **WHEN** a network Event is redacted for telemetry
- **THEN** its source IP/port and HTTP path are empty and its destination and method are retained
