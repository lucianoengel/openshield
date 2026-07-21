## ADDED Requirements

### Requirement: Signed telemetry is verified before it is persisted
The control plane MUST verify signed telemetry — the signature against the ENROLLED agent key and
the sequence for replays — before persisting it, attribute it to the VERIFIED agent, and REJECT and
count telemetry that fails (bad signature, unknown or revoked agent, replay). A sequence gap MUST be
recorded, not silently accepted.

Per-agent identity (D44) exists but was never applied to the telemetry stream, so the fleet view was
self-asserted (D41) and suppression undetectable. Verifying on ingest makes telemetry attributable
and gaps visible — the evidentiary bar telemetry needs.

#### Scenario: A validly signed message is verified and stored as attributable
- **WHEN** an enrolled agent publishes correctly signed telemetry
- **THEN** it verifies and is persisted attributed to that agent, marked verified
- **AND** a test drives it over an embedded NATS and asserts the stored, verified row

#### Scenario: An unverifiable message is rejected and counted
- **WHEN** telemetry arrives with a bad signature, from an unknown or revoked agent, or replaying a
  sequence
- **THEN** it is NOT persisted and a rejection is counted
- **AND** tests assert each case increments the rejection count and stores nothing

#### Scenario: A sequence gap is recorded
- **WHEN** a validly signed message arrives with a sequence beyond the next expected
- **THEN** the message is stored and the gap is recorded
- **AND** a test asserts the gap is observable

### Requirement: Verified and self-asserted telemetry are distinguishable
Persisted telemetry MUST record whether it was verified against an enrolled key or arrived on the
legacy unsigned path (self-asserted). The unsigned path MUST NOT be silently treated as verified.

An aggregate that cannot tell attributable telemetry from self-asserted invites the same overclaim
the project forbids — presenting unverified data as evidence. The distinction must be in the data.

#### Scenario: The stored row carries its verification status
- **WHEN** telemetry is persisted via the signed path and via the legacy unsigned path
- **THEN** the signed one is marked verified and the legacy one is marked self-asserted
- **AND** a test asserts both
