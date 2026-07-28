

## Purpose

Making a response leave the platform: a ticket in someone else's queue, an account disabled in someone
else's IdP. A connector acts only on the verbs it declares, four-eyes is re-checked by the runner rather
than trusted from upstream, every execution records the intent id and the call it made, and an intent
executes at most once per connector. Ticket content carries no evidence, the closed-status vocabulary
and connector name are the operator's, and sync-back can never move an incident's lifecycle backwards.

## Requirements

### Requirement: A matching incident opens exactly one ticket

The system SHALL open at most one ticket per (connector, incident), enforced by the database, and SHALL
record the remote reference so the incident and the ticket are linked in both directions. Repeated sync
runs MUST NOT open a second ticket.

#### Scenario: A matching incident is ticketed once
- **WHEN** the sync runs repeatedly over a matching incident
- **THEN** exactly one ticket exists for it, carrying the remote reference

#### Scenario: A non-matching incident is not ticketed
- **WHEN** an incident is below the configured severity floor
- **THEN** no ticket is opened

### Requirement: Only a declared closed-status closes an incident

A connector SHALL declare the CLOSED set of remote statuses that mean the ticket is closed. A status
outside that set SHALL be ignored and MUST NOT close the incident. Treating an unrecognised remote status
as "closed" would let a vocabulary change in someone else's system silently stop an incident being
investigated.

#### Scenario: A declared closed status transitions the incident
- **WHEN** the ticket's status is one the connector declares as closed
- **THEN** the incident is transitioned to closed

#### Scenario: An unknown status changes nothing
- **WHEN** the ticket's status is not in the declared set
- **THEN** the incident's state is unchanged

### Requirement: Sync-back cannot move the incident lifecycle backwards

Status sync-back SHALL respect the forward-only lifecycle. A reopened ticket SHALL NOT reopen or otherwise
move its incident backwards. The lifecycle is forward-only so response-time metrics remain measurable, and
an external system does not get to override that; an incident that needs reopening becomes a new incident.

#### Scenario: A reopened ticket does not reopen the incident
- **WHEN** a closed ticket returns to an open status
- **THEN** the incident remains closed

### Requirement: A sync-back transition is attributed to the connector

A transition made by sync-back SHALL record the connector as the actor, never an operator identity. A
machine's decision recorded under a human's name is a corrupted audit trail, and it would also corrupt the
acknowledgement attribution that response metrics depend on.

#### Scenario: The transition names the connector
- **WHEN** sync-back closes an incident
- **THEN** the recorded actor identifies the connector, not a person

### Requirement: Ticket content carries no evidence

A created ticket SHALL carry the incident's pseudonymous subject and closed-vocabulary metadata only. It
SHALL NOT carry evidence content, file contents, or classifier output beyond type and count.

#### Scenario: The ticket body is metadata only
- **WHEN** a ticket is created
- **THEN** its body contains the pseudonymous subject, severity and counts, and no evidence content

### Requirement: The closed vocabulary and connector identity are the operator's

The ticketing connector's CLOSED vocabulary SHALL be operator-configured, and the configured list SHALL
REPLACE the shipped default rather than extend it — a deployment whose ticketing system says "erledigt"
must not also close incidents on a status it never declared. The connector's NAME SHALL be
operator-configured and recorded on the incident⇄ticket link, so two configured ticketing systems can be
told apart.

An unresponsive remote system SHALL NOT wedge the sync loop: the configured request timeout SHALL bound
each attempt, and the loop SHALL keep retrying on its interval.

#### Scenario: A configured closed status closes its incident
- **WHEN** the remote ticket reports a status in the operator's configured closed vocabulary
- **THEN** the linked incident is closed

#### Scenario: A default status outside the configured vocabulary does not
- **WHEN** the remote ticket reports a status from the shipped default list that this deployment has not configured
- **THEN** the linked incident is not closed

#### Scenario: An unresponsive ticketing system does not stop the loop
- **WHEN** the remote system accepts connections and never answers
- **THEN** each attempt is abandoned within the configured timeout and the loop continues retrying

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

<!-- restored from 2026-07-26-soar8-idp-responder -->

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

<!-- restored from 2026-07-26-soar8-idp-responder -->

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

<!-- restored from 2026-07-26-soar8-idp-responder -->

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

<!-- restored from 2026-07-26-soar8-idp-responder -->

### Requirement: The irreversibility is stated where the connector is configured

Documentation and operator-facing output for this connector SHALL state that its actions cannot be undone
by intent expiry. Every other intent enactment in the platform is restored when the intent lapses, so an
operator's reasonable expectation is wrong here unless it is corrected explicitly.

#### Scenario: Expiry restores nothing
- **WHEN** an executed intent later expires
- **THEN** no compensating call is made, and the recorded action stands

<!-- restored from 2026-07-26-soar8-idp-responder -->
