## ADDED Requirements

### Requirement: Agents report their actual enforcement state

An agent's liveness signal SHALL carry whether its enforcement is disabled and the highest fleet-control
sequence it has applied. The reported state SHALL be the agent's ACTUAL state, so an agent disabled by a
local break-glass file is visible — the control plane has no other way to learn that.

#### Scenario: A disabled agent is visible
- **WHEN** an agent reports that enforcement is disabled
- **THEN** the fleet summary counts it as disabled

#### Scenario: A locally disabled agent is visible
- **WHEN** an agent is disabled by a local file and has applied no fleet control
- **THEN** it is still counted as disabled

#### Scenario: The latest report wins
- **WHEN** an agent reports a new state
- **THEN** the summary reflects the newer state and the agent is counted once

### Requirement: The fleet summary answers arrival and lag

The system SHALL report how many agents are enforcing, how many are disabled, and how many have not
applied the current control. Publication is best-effort, so without this an operator cannot tell a
delivered disable from an undelivered one.

#### Scenario: Agents behind the current control are counted
- **WHEN** some agents have applied an older sequence than the current control
- **THEN** they are reported as not caught up

### Requirement: Silence is not reported as compliance

The summary SHALL reflect only what agents have reported. An agent that has gone silent MUST NOT be
counted as enforcing or as disabled on the strength of an old report being absent; detecting absence
remains the overdue mechanism's responsibility.

#### Scenario: The summary does not infer state for unseen agents
- **WHEN** an agent has never reported
- **THEN** it contributes nothing to the summary rather than a default state
