## ADDED Requirements

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
