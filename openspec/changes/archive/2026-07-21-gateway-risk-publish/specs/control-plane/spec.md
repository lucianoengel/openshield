# control-plane delta

## ADDED Requirements

### Requirement: The control plane publishes per-subject risk to the gateways
The control plane MUST be able to publish a per-subject risk update, so a gateway can read it for
continuous verification. It MUST publish risk when it detects an anomalous subject, best-effort — a
publish failure MUST NOT break telemetry ingest. The published risk is data the gateway interprets; the
control plane MUST NOT command the gateway to act.

#### Scenario: A detected anomaly publishes a risk update
- **WHEN** the control plane records a peer alert for a subject
- **THEN** it publishes a risk update for that subject
