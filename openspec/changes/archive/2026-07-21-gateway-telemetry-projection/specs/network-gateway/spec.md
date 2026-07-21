# network-gateway delta

## ADDED Requirements

### Requirement: The gateway projects decisions to the control plane, boundary-safe and opt-in
When a telemetry transport is configured, the gateway MUST project each Decision — with a redacted
network Event — to the control plane through the signed transport, additively to the local ledger. It
MUST NOT project when no transport is configured (the default), MUST NOT fail the request on a
projection error (the local ledger is the system of record), and the projected network metadata MUST
omit the user IP and the URL path while retaining the destination and verdict.

#### Scenario: A decision projects a redacted network Event plus the Decision
- **WHEN** the gateway processes a network request with a telemetry transport configured
- **THEN** it publishes the Decision and a network Event whose src_ip and http_path are empty and whose
  destination (sni_host / dst) is retained

#### Scenario: No projection without a transport
- **WHEN** the gateway processes a request with no telemetry transport configured
- **THEN** nothing is projected

#### Scenario: A projection failure does not fail the request
- **WHEN** the telemetry transport returns an error while projecting
- **THEN** the request still completes and the decision remains recorded locally
