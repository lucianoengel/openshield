# control-plane

## ADDED Requirements

### Requirement: The fleet roster reports what each agent says it is running

The roster SHALL report each agent's platform, release version and offline-queue depth as reported by
that agent, and SHALL report each as ABSENT where the agent did not report it.

An agent built before these fields existed sends none of them, and the protocol's zero values are claims:
an empty version reads as one that could not be determined, and a zero queue depth reads as an empty
queue on a host that may be spooling hard.

#### Scenario: An older agent is reported as not having said
- **WHEN** an agent reports liveness without inventory
- **THEN** its platform, version and queue depth are reported absent rather than as empty or zero

#### Scenario: The latest report wins
- **WHEN** an agent reports a new version after an upgrade
- **THEN** the roster reports the new one
