

## Purpose

A reusable approval object for actions one person should not take alone: requester and approver must be
different operators, the rule enforced atomically rather than checked; a pending request expires; an
outcome is terminal and attributed; and the request names what it is for. Automation may REQUEST an
approval but only a human may grant one, and the requesting feature — not this capability — decides what
a refusal means.

## Requirements

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

### Requirement: An approval requires a second, different operator

The system SHALL record an approval request naming its subject and requester, and SHALL allow it to be
approved only by an operator DIFFERENT from the requester. The comparison SHALL be enforced inside the
write predicate so that concurrent attempts cannot both succeed — a check performed before the write is a
race, not a control.

#### Scenario: The requester cannot approve their own request
- **WHEN** the operator who requested an approval attempts to approve it
- **THEN** it is refused and the request remains pending
- **AND** the test FAILS if the requester's approval is applied

#### Scenario: A different operator approves
- **WHEN** an operator other than the requester approves a pending request
- **THEN** the request is approved and records who approved it and when

#### Scenario: Concurrent approvals produce exactly one outcome
- **WHEN** several operators approve the same pending request simultaneously
- **THEN** exactly one approval succeeds and the rest are refused as no longer pending

<!-- restored from 2026-07-26-soar3-approvals -->

### Requirement: A pending approval expires

An approval request SHALL carry an expiry. Once past it, the request SHALL NOT be approvable, and its state
SHALL reflect that it expired rather than remaining pending forever.

An approval request left open indefinitely is not consent; treating a week-old request as live is how
"somebody approved it eventually" becomes the norm.

#### Scenario: An expired request cannot be approved
- **WHEN** an approval is attempted after the request's expiry
- **THEN** it is refused as expired, not approved
- **AND** the test FAILS if expiry is ignored

<!-- restored from 2026-07-26-soar3-approvals -->

### Requirement: An approval outcome is terminal and attributed

Approving, denying or expiring SHALL be terminal: an already-resolved request SHALL NOT be re-approved or
re-denied. Every outcome SHALL record the operator responsible and the time.

#### Scenario: A resolved request cannot be resolved again
- **WHEN** an approved or denied request receives another decision
- **THEN** it is refused and the original outcome and attribution are unchanged

<!-- restored from 2026-07-26-soar3-approvals -->

### Requirement: An approval names what it is for

Every approval SHALL carry a subject KIND and a subject id, so a consumer can find the approval for a
specific playbook step, response intent, or case — and so an approval for one subject can never be
mistaken for approval of another.

#### Scenario: An approval is bound to its subject
- **WHEN** an approval is recorded for one subject
- **THEN** it is retrievable by that subject kind and id, and does not satisfy a different subject

<!-- restored from 2026-07-26-soar3-approvals -->

### Requirement: Automation may request an approval, but only a human may grant it

An approval request opened by automation SHALL record the requester as the automation's own identity —
for a playbook step, `playbook:<name>` — and never as an operator identity, so the audit trail never attributes a machine's request to a human who did not make it.
Because no human requested it, the requester≠approver rule cannot mean *two humans*: an
automation-initiated request is a **human-in-the-loop gate** requiring exactly **one** operator approval.
This SHALL be stated wherever the control is described, so it is not mistaken for two-person integrity.

#### Scenario: A playbook step's request records the playbook as requester
- **WHEN** a `wait-for-approval` step opens a request
- **THEN** the stored requester is the playbook identity, and any operator may resolve it

#### Scenario: A subject's approval cannot satisfy another subject
- **WHEN** an approval exists for one run and step
- **THEN** it does not satisfy a different run or step — the lookup is keyed by both parts of the subject

<!-- restored from 2026-07-26-soar4-playbook-engine -->

### Requirement: The requesting feature decides what a refusal means

The approval object SHALL report the outcome (approved, denied, expired, still pending) and nothing more.
What a refusal *does* — abort, retry, escalate, proceed degraded — SHALL be decided by the requesting
feature, because the approval object cannot know the consequence of the action it gates.

#### Scenario: A denial is reported, not acted upon
- **WHEN** a request is denied
- **THEN** the approval records the denial and its approver, and the consuming feature (for a playbook, by
  failing the run) determines the effect

<!-- restored from 2026-07-26-soar4-playbook-engine -->
