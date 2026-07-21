# event-transport delta

## ADDED Requirements

### Requirement: Real endpoint detections reach the verified telemetry stream
The endpoint engine MUST be able to publish its real detections (Event + Decision) to the control plane
through the signed transport, so fleet visibility, peer analytics, and the dead-man's-switch operate
over real endpoint detections rather than only a simulator. Publishing MUST be signed by an enrolled
identity and MUST be opt-in (enabled only when transport and enrollment are configured).

#### Scenario: An enrolled engine publishes a real detection
- **WHEN** an engine configured with transport and an enrolled identity produces a detection
- **THEN** the signed Event and Decision are published to the control plane's verified stream
