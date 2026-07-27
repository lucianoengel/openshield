

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

### Requirement: The emergency disable is reachable from the shipped binaries

Every component that ENFORCES SHALL install the kill switch, watch its local break-glass file, and — when
given a control-plane key and a broker — accept signed fleet-wide control. The control plane SHALL provide
an operator-local means of issuing one.

This is a requirement about WIRING, and it is stated separately because the mechanism existing is not the
same as the mechanism being reachable: a kill switch that no command installs, a channel no command
subscribes to, and a control nothing can sign together look, from outside, exactly like a feature that was
never built — while its unit tests report that it works.

Accepting fleet control SHALL NOT depend on enrollment. A component that cannot publish telemetry is not
the one that should be impossible to stop.

#### Scenario: An issued fleet disable stops a running component enforcing
- **WHEN** an approved, signed fleet disable is published
- **THEN** every running component subscribed to the channel stops enforcing, keeps detecting and
  auditing, and continues running

#### Scenario: Both enforcement call sites honour the same control
- **WHEN** a fleet disable is published
- **THEN** the network component and the endpoint component both apply it

#### Scenario: The local break-glass path works without a control plane
- **WHEN** the break-glass file appears on a host with no broker and no control-plane key
- **THEN** that host stops enforcing, and names the reason the file gave

#### Scenario: Absence of the break-glass file is never engagement
- **WHEN** no break-glass file exists
- **THEN** enforcement continues

#### Scenario: An unapproved fleet disable is never published
- **WHEN** a disable is issued without an approved four-eyes approval bound to its control id
- **THEN** nothing is signed or sent
