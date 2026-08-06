# heartbeat

## ADDED Requirements

### Requirement: The endpoint agent that runs the pipeline emits the liveness signal

The binary that observes, classifies and enforces SHALL publish a heartbeat on an interval. A simulator
publishing one SHALL NOT be treated as satisfying this.

Until this, the only producer in the tree was the fleet simulator, so on every real deployment the
dead-man's-switch advanced last-seen only from detections — and an idle endpoint that had detected
nothing was indistinguishable from one that had been killed, which is the precise failure the heartbeat
exists to prevent.

#### Scenario: An idle endpoint is still reported alive
- **WHEN** an endpoint agent runs and produces no detections
- **THEN** its last-seen advances from the heartbeat alone

#### Scenario: Disabling the heartbeat is announced
- **WHEN** the heartbeat interval is configured to zero or less
- **THEN** the agent reports at startup that it will look silent whenever it is merely idle

### Requirement: The heartbeat carries the agent's own inventory

The heartbeat SHALL carry the agent's platform, the release it was built from, and the depth of its
durable offline queue. It SHALL NOT carry an attestation verdict or a posture conclusion, because a
self-report is not evidence of trustworthiness.

#### Scenario: An unstamped build is identifiable as one
- **WHEN** an agent was built without a release version
- **THEN** it reports a value meaning "unreleased build" rather than an empty one
