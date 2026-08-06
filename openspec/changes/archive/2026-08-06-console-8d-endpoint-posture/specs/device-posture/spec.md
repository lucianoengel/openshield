# device-posture

## ADDED Requirements

### Requirement: The endpoint that runs the pipeline publishes its own device posture

The binary that observes, classifies and enforces SHALL be able to publish signed device posture. A
simulator publishing it SHALL NOT be treated as satisfying this.

Absent posture is untrusted by design, so with no real producer a posture-requiring policy denied every
genuine endpoint and admitted only simulated ones.

#### Scenario: A posture-requiring policy admits an endpoint that reports
- **WHEN** a posture-requiring policy denies a device that has published none
- **AND** that device's endpoint agent then publishes signed posture
- **THEN** the same request from the same identity is admitted

#### Scenario: An endpoint without a posture key states the consequence
- **WHEN** an endpoint starts with no posture signing key
- **THEN** it reports that a posture-requiring gateway will deny it

#### Scenario: A configured but unusable posture key stops the endpoint
- **WHEN** a posture signing key is configured and cannot be used
- **THEN** the endpoint refuses to start rather than run silently unreported

### Requirement: Binary integrity travels with posture and has three states

The posture report SHALL carry whether the endpoint's installed files match the release they claim, as
one of verified, mismatched, or not checked. A failure to determine it SHALL be reported as not checked.

Reported only to a local log, the answer lives on the host that may itself be compromised. Carried on
posture, it becomes a fleet-wide question decided where the endpoint has no vote.

#### Scenario: An undeterminable answer is not guessed
- **WHEN** the integrity check cannot run or is not configured
- **THEN** the report says not checked, never verified and never mismatched

#### Scenario: The answer is not cached across the endpoint's lifetime
- **WHEN** posture is republished
- **THEN** binary integrity is re-determined rather than reused
