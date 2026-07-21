# enforcement delta

## ADDED Requirements

### Requirement: A flow enforcer resolves a flow_id target through a pluggable flow table
A flow enforcer MUST implement the existing `core.TargetedEnforcer`, advertise the network verdicts it
can carry out (BLOCK and REDIRECT), and resolve the `flow_id` enforce target to an action through a
`FlowTable` seam (`Block`/`Redirect` by flow id) rather than assuming a live socket. It MUST refuse to
act without a flow_id target, and MUST reject any action it does not advertise. This proves the
existing target-string enforcer interface generalises to a second domain (after files) with no change
to the enforcer interface.

#### Scenario: A BLOCK verdict is dispatched to the flow enforcer and reaches the flow table
- **WHEN** a BLOCK Decision is dispatched to a flow enforcer with a flow_id target
- **THEN** the enforcer invokes the flow table's block operation for that flow_id

#### Scenario: A REDIRECT verdict reaches the flow table's redirect operation
- **WHEN** a REDIRECT Decision is dispatched to a flow enforcer with a flow_id target
- **THEN** the enforcer invokes the flow table's redirect operation for that flow_id

#### Scenario: The flow enforcer refuses an action it does not advertise
- **WHEN** a Decision with an action outside {BLOCK, REDIRECT} reaches the flow enforcer
- **THEN** the enforcer returns an error rather than acting
