# control-plane delta

## ADDED Requirements

### Requirement: A restarted agent's telemetry is not rejected as a replay
The control plane MUST accept telemetry from an agent that has restarted with a persisted, forward
sequence — recording a gap if one occurred — rather than rejecting it as a replay, so a routine restart
does not silently drop an agent's telemetry.

#### Scenario: Post-restart telemetry is accepted, not replayed
- **WHEN** an agent restarts, resumes from its persisted high-water sequence, and publishes
- **THEN** VerifySigned accepts the telemetry (a gap at most), not ErrReplay
- **AND** a test drives a restart-then-publish and asserts acceptance, not replay rejection
