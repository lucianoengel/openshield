## ADDED Requirements

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
