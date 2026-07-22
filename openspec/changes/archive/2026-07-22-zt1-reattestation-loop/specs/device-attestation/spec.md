## ADDED Requirements

### Requirement: Continuous re-attestation from the endpoint

The system SHALL let an endpoint re-attest on an interval so the gateway's attested signal tracks the
device's current state: after a device's measured state drifts from its enrolled baseline, a subsequent
re-attestation MUST be rejected by the gateway and the device MUST lose its attested status. A
re-attestation failure MUST NOT be fatal to the endpoint.

#### Scenario: A good device stays attested across cycles

- **WHEN** an enrolled device runs the re-attestation loop in its golden state
- **THEN** the gateway keeps it attested across successive cycles

#### Scenario: A drifted device loses attestation within a cycle

- **WHEN** an enrolled device's PCR state drifts after enrollment while the loop is running
- **THEN** the gateway rejects the next re-attestation and the device is no longer attested
