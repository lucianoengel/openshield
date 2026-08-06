# control-plane

## ADDED Requirements

### Requirement: The operator surface serves the fleet roster

The operator surface SHALL serve every enrolled agent with its enrollment time, whether it is revoked, when
it was last seen from VERIFIED telemetry, how long it has been silent, and its self-reported enforcement
state with the fleet sequence it has applied.

#### Scenario: An enrolled agent with no telemetry reports never-seen
- **WHEN** an agent is enrolled and has sent no verified telemetry
- **THEN** its last-seen is reported as absent rather than as the zero time

#### Scenario: Unverified telemetry does not advance last-seen
- **WHEN** unverified telemetry exists for an agent
- **THEN** it does not contribute to that agent's last-seen

#### Scenario: An agent that has never reported enforcement is distinguishable from one enforcing
- **WHEN** an agent has sent no enforcement acknowledgement
- **THEN** its enforcement state is reported as unknown rather than as enforcing

### Requirement: The operator surface serves the break-glass register

The operator surface SHALL serve the recorded fleet controls, each with whether it still stands, and SHALL
serve the derived answer to whether enforcement is currently suppressed fleet-wide.

#### Scenario: A standing disable is distinguishable from a lapsed one
- **WHEN** the register contains one unexpired disable and one expired disable
- **THEN** only the unexpired one is reported as standing

### Requirement: The fleet roster and break-glass register are gated at the lowest operator tier

Both surfaces SHALL be reachable at the analyst tier and MUST NOT be reachable without an operator
credential.

The roster is already exposed at this tier by the overdue surface, so gating it higher would be a control
with a door beside it; and an analyst who does not know a host was not enforcing will misread the evidence
that host produced.

#### Scenario: An anonymous caller is refused
- **WHEN** a caller presents no operator credential
- **THEN** the fleet surfaces are refused
