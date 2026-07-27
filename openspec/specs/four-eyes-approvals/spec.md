

### Requirement: Opening an approval request notifies

Requesting an approval SHALL emit a notification so the operators who could approve it learn that it
exists. Without this, a four-eyes request waits for someone who was never told — and an automated
playbook step gated on approval parks indefinitely on a decision nobody knows is pending.

The notification SHALL carry the approval's subject kind and id so a recipient can find it, and SHALL NOT
carry the requester's reason text verbatim in a field the routing layer matches on.

#### Scenario: A requested approval is announced
- **WHEN** an approval request is opened
- **THEN** a notification of the approval-pending kind is emitted naming the approval and its subject

#### Scenario: Notification failure does not fail the request
- **WHEN** the notification cannot be delivered
- **THEN** the approval request is still recorded — the database row is the record, delivery is additive

### Requirement: The four-eyes controls are reachable by an operator

Every four-eyes operation SHALL be invocable by an authenticated operator through the product's own
surface. A control that exists and cannot be exercised provides no assurance: its unit tests pass, and no
deployment can apply it.

The identity compared by a four-eyes check SHALL come from the caller's verified certificate, never from a
request field. Four-eyes is arithmetic on identities; if a caller can name themselves, the requester and
the approver are whoever the caller says they are.

#### Scenario: The requester cannot approve their own request
- **WHEN** the operator who requested a closure attempts to approve it
- **THEN** the request is refused and the case remains open

#### Scenario: A second operator can approve
- **WHEN** a different authenticated operator approves
- **THEN** the case closes and the record names both operators

#### Scenario: Acting requires more than reading
- **WHEN** an operator holding only the read tier attempts a case action
- **THEN** it is refused
