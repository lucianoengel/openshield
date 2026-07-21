# fleet-simulation Specification

## Purpose
A one-command multi-agent fleet simulation in podman: N agent containers enroll with their own identities and publish verified telemetry, and it asserts the fleet properties (verified+attributed telemetry, liveness, the dead-man's-switch on a killed agent, revocation rejecting telemetry). deploy/fleet-e2e.sh; token issuance is an operator-local command; fanotify permission mode is not simulable in rootless podman.
## Requirements
### Requirement: A multi-agent fleet is demonstrable in podman
There MUST be a one-command simulation that brings up the control plane and multiple agent
containers, each enrolling with its own identity and publishing verified telemetry, and ASSERTS the
fleet properties: telemetry is verified and attributed per agent, each agent is seen, a killed agent
becomes overdue, and a revoked agent's telemetry is rejected. It MUST tear down and restore the dev
database on any exit.

Identity, enrollment, signed telemetry, heartbeat and revocation are unit-tested in isolation but
never together at fleet scale. A running multi-agent simulation is where their integration is
proven — the fleet analogue of the endpoint walking skeleton.

#### Scenario: The fleet properties hold across real containers
- **WHEN** the fleet simulation runs
- **THEN** each agent's telemetry is stored verified and attributed to it, each agent is seen, a
  killed agent is reported overdue by the dead-man's-switch, and a revoked agent's subsequent
  telemetry is rejected
- **AND** the simulation asserts these and exits non-zero if any fails

#### Scenario: Token issuance is an operator command, not a network route
- **WHEN** the simulation mints tokens for its agents
- **THEN** it does so via an operator-local command run inside the control-plane container, not a
  network endpoint
- **AND** the simulation restores the dev database on any exit

