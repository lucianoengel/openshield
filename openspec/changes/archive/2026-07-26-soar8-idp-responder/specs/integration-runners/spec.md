## ADDED Requirements

### Requirement: A connector acts only on the verbs it declares

Each integration connector SHALL declare a CLOSED set of intent verbs it handles and, for each, the closed
set of actions it performs. An intent carrying a verb outside that set SHALL be ignored, not improvised
into an action. This is the same reasoning that closes the Action set, the intent vocabulary and the
playbook step registry: a component that can be made to perform an operation nobody enumerated is an open
action framework, and this one reaches outside the platform.

#### Scenario: An undeclared verb performs nothing
- **WHEN** an intent carries a verb the connector does not declare
- **THEN** no external call is made and no action is recorded

#### Scenario: A declared verb performs exactly its declared actions
- **WHEN** an intent carries a declared verb
- **THEN** the connector performs that verb's declared actions and no others

### Requirement: Four-eyes is required for every executed intent and re-checked by the runner

The runner SHALL refuse to execute an intent unless an approval bound to that intent's id is in the
approved state — for EVERY verb, including verbs whose publication required no approval. The runner SHALL
perform this check itself rather than relying on the publisher having performed it.

Publication gating protects against publishing the wrong intent. It does not protect against a runner
executing an intent that reached it some other way, and a component taking an irreversible action on an
external system must not delegate its authorization check to the component that asked for the action.

#### Scenario: An unapproved intent is never executed
- **WHEN** an intent has no approval, or its approval is pending, denied or expired
- **THEN** no external call is made

#### Scenario: An approval for one intent does not authorize another
- **WHEN** an approval exists for a different intent id
- **THEN** the intent is not executed

#### Scenario: An expired intent is not executed
- **WHEN** the intent's own validity has lapsed
- **THEN** no external call is made, regardless of approval

### Requirement: Every execution records the intent id and the call it made

The runner SHALL durably record, for each action, the intent id, the connector, the verb, the subject, the
target that was called, the outcome, and the time. An irreversible action with no record of what triggered
it cannot be explained to the person it was applied to.

#### Scenario: The record links intent to call
- **WHEN** an approved intent is executed
- **THEN** a record exists naming the intent id and the target that was called, with the call's outcome

#### Scenario: A failed call is recorded, not discarded
- **WHEN** the external call fails
- **THEN** the failure and its cause are recorded against the intent id

### Requirement: An intent executes at most once per connector

The runner SHALL execute a given intent at most once per connector. A redelivered or replayed intent MUST
NOT repeat the action. The claim SHALL be taken BEFORE the external call, so an interruption leaves a
visible claimed record rather than an action that silently repeats on the next delivery.

#### Scenario: Redelivery does not repeat the action
- **WHEN** the same intent is delivered twice
- **THEN** exactly one external call is made

#### Scenario: An interrupted execution is visible
- **WHEN** an execution is claimed but does not complete
- **THEN** the record remains in the claimed state rather than being absent

### Requirement: The irreversibility is stated where the connector is configured

Documentation and operator-facing output for this connector SHALL state that its actions cannot be undone
by intent expiry. Every other intent enactment in the platform is restored when the intent lapses, so an
operator's reasonable expectation is wrong here unless it is corrected explicitly.

#### Scenario: Expiry restores nothing
- **WHEN** an executed intent later expires
- **THEN** no compensating call is made, and the recorded action stands
