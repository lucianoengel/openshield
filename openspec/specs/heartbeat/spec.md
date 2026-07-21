# heartbeat Specification

## Purpose
The dead-man's-switch backing D16: agents heartbeat, the control plane tracks last-seen per host, and a pure detector flags a host silent past a threshold as OVERDUE - a signal for a human, not an accusation, defeatable by root and stated as such.
## Requirements
### Requirement: The control plane tracks when each agent was last seen
The agent MUST emit periodic heartbeats, and the control plane MUST record the latest per host so
"when did we last hear from agent X" is a queryable fact, updated whether the agent sent telemetry
or only a heartbeat.

Tamper-DETECTION (D16) is only real if the ABSENCE of an agent is detectable. An idle agent that
reports nothing would otherwise look identical to a stopped one; a heartbeat is what makes "still
here" distinct from "gone".

#### Scenario: A heartbeat updates last-seen
- **WHEN** an agent publishes a heartbeat and the control plane is subscribed
- **THEN** the agent's last-seen advances to the heartbeat time
- **AND** a test drives it over an embedded NATS and asserts last-seen

### Requirement: Silence past a threshold marks an agent overdue
The control plane MUST identify agents whose last-seen is older than a configured threshold as
OVERDUE. The detection MUST be a pure function of last-seen times and the threshold, so it is
verifiable without infrastructure.

A healthy agent heartbeats on an interval, so silence beyond several intervals means stopped,
masked, disconnected or dead. Overdue is a SIGNAL for a human to investigate, not an accusation of
tampering — legitimate offline periods exist, and the offline queue means brief gaps self-heal.

#### Scenario: An agent silent past the threshold is overdue; a recent one is not
- **WHEN** the detector runs with one agent last seen long ago and one seen recently
- **THEN** the first is reported overdue and the second is not
- **AND** a table test asserts the boundary directly

### Requirement: The claim is stated as detection of the common case, not prevention
Any surface describing the heartbeat MUST state that it is defeatable by root and by a compromised
control plane, and that overdue is a signal, not proof of tampering.

D16 is explicit: anyone with root defeats a host agent. A heartbeat that implied otherwise would be
the overclaim the project forbids. Its honest value is noticing the common, non-adversarial case —
an agent that died or a host that went offline — not defeating an adversary who owns both ends.

#### Scenario: No surface claims the heartbeat is tamper-proof
- **WHEN** the heartbeat is described in docs
- **THEN** it is described as detection of the common case, defeatable by root / a compromised
  control plane, and overdue as a signal not an accusation

