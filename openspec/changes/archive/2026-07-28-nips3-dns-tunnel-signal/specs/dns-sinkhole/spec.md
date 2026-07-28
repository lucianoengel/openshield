# dns-sinkhole

## ADDED Requirements

### Requirement: A live DNS query MUST carry a tunnelling signal into the policy input

For each observed DNS query event, the engine MUST derive a tunnelling likelihood score from the
queried name and expose it to policy evaluation as a typed input, so that a policy can decide on
it.

The input MUST be ABSENT for events that are not DNS queries, rather than present with a
default value — an absent input tells a policy that nothing was assessed, and a fabricated value
tells it something was.

The score MUST be derived from the name only. No query payload, and no content beyond the
metadata the connector already parsed, may be introduced by the derivation.

#### Scenario: A tunnelling name is scored

- **WHEN** a DNS query is observed whose name carries long, high-entropy labels
- **THEN** the policy input for that event MUST include a tunnelling score

#### Scenario: A non-DNS event carries no tunnelling input

- **WHEN** a filesystem or process event is evaluated
- **THEN** the tunnelling input MUST be absent from its policy input

### Requirement: The default policy MUST alert on a high tunnelling score and MUST NOT block

The shipped default policy MUST raise an ALERT when a DNS query's tunnelling score reaches the
configured threshold, and MUST NOT deny the query.

Denial is reserved for an operator raising the action deliberately. A heuristic over a single
query, with no session context, that automatically denied name resolution would turn one false
positive into a resolution outage.

#### Scenario: A tunnelling query alerts

- **WHEN** a DNS query scores at or above the configured tunnelling threshold
- **THEN** the decision MUST be ALERT
- **AND** an audit entry MUST be recorded

#### Scenario: An ordinary query does not alert

- **WHEN** a DNS query for a short, low-entropy name is observed
- **THEN** the decision MUST NOT be an alert arising from the tunnelling rule

### Requirement: The tunnelling threshold MUST be refused when outside the score's range

The tunnelling threshold MUST be a validated configuration setting constrained to the range the
score can take, and a value outside that range MUST be refused when it is set.

A threshold a score can never reach silently disables a detector while the process reports it as
enabled — the failure mode is indistinguishable from "nothing suspicious happened" on a console.

#### Scenario: An out-of-range threshold is refused at save

- **WHEN** an operator sets the tunnelling threshold to a value outside the score's range
- **THEN** the setting MUST be refused with an error naming the field

### Requirement: A DNS decision's audit entry MUST NOT contain the queried name

An audit entry arising from a DNS query MUST NOT record the queried name or any label of it.

This requirement is more acute than the general content-free rule it follows from: in a DNS
tunnel, the exfiltrated data IS the name. An evidence trail that recorded it would republish the
exfiltration it exists to detect, into the system's most copied and longest-retained store.

#### Scenario: The tunnelled payload does not reach the ledger

- **WHEN** a DNS query encoding data in its subdomain labels is decided upon
- **THEN** no audit entry may contain the encoded labels
