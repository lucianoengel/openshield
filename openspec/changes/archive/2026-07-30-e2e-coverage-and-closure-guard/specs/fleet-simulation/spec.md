## MODIFIED Requirements

### Requirement: A multi-agent fleet is demonstrable in podman

There MUST be a one-command simulation that brings up the control plane and multiple agents, each
enrolling with its own identity and publishing verified telemetry, and ASSERTS the fleet properties:
telemetry is verified and attributed per agent, each agent is seen, a killed agent becomes overdue,
and a revoked agent's telemetry is rejected. It MUST tear down and restore the dev database on any
exit.

Identity, enrollment, signed telemetry, heartbeat and revocation are unit-tested in isolation but
never together at fleet scale. A running multi-agent simulation is where their integration is
proven — the fleet analogue of the endpoint walking skeleton.

**Agents are PROCESSES, not containers, and the wording here previously said containers.** Podman
hosts the infrastructure (Postgres, NATS); the agents are `openshield-fleet-agent` processes on one
host, and the largest fleet exercised anywhere is six. That is a reasonable engineering choice for
the properties below — per-agent identity, enrollment, heartbeat and revocation do not need separate
network namespaces to be proven. The requirement is corrected rather than the topology changed,
because a spec claiming containers describes coverage the suite does not have.

#### Scenario: The fleet properties hold across multiple independent agents
- **WHEN** the fleet simulation runs
- **THEN** each agent's telemetry is stored verified and attributed to it, each agent is seen, a
  killed agent is reported overdue by the dead-man's-switch, and a revoked agent's subsequent
  telemetry is rejected
- **AND** the simulation asserts these and exits non-zero if any fails

## ADDED Requirements

### Requirement: The properties that need separate machines are named as unproven

The simulation's limits SHALL be recorded rather than implied. Running agents as processes on one
host cannot exercise the failures that exist only between machines, and a simulation described as a
fleet invites the reader to assume otherwise.

Specifically unproven today: **network partition and rejoin**, **clock skew between an agent and the
control plane**, **per-node resource limits under real contention**, and **offline-queue drain after
a real disconnection**. These are the failures an enterprise pilot encounters first, which is why
leaving them implied is the expensive option.

#### Scenario: A limit is stated rather than left to inference
- **WHEN** the fleet simulation's coverage is described
- **THEN** the four properties above are named as not exercised, and the reason is the topology
  rather than an oversight
