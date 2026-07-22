## ADDED Requirements

### Requirement: Attestation challenge and report transport

The system SHALL carry a device attestation exchange over the messaging channel: a device requests a
fresh nonce for its subject and receives it, then publishes a report containing its quote over that
nonce, and the gateway verifies each received report through the attestation verifier. A report that
fails verification MUST be dropped and counted, never silently accepted, and the transport MUST NOT add a
second authentication layer over the quote — the quote authenticates itself against the enrolled AK.

#### Scenario: A device attests over the live channel

- **WHEN** an enrolled device requests a challenge, quotes over the returned nonce, and publishes the
  report
- **THEN** the gateway verifies the report and marks the device attested

#### Scenario: A forged or stale report on the channel is rejected

- **WHEN** a report with a mismatched nonce or a quote not signed by the enrolled AK is published
- **THEN** the gateway rejects it, counts it, and does not mark the device attested
