# four-eyes-approvals Specification

## Purpose
A reusable four-eyes control (SOAR-3), generalized from case closure (D36): an approval request names its
subject and requester, and only a DIFFERENT operator can approve it. Every condition — still pending, not
expired, approver≠requester — is enforced inside the write predicate, which is what makes it a control
rather than a check that a race can defeat. Requests expire, outcomes are terminal and attributed, and an
approval is bound to its subject so it can never satisfy another.

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

### Requirement: A pending approval expires

An approval request SHALL carry an expiry. Once past it, the request SHALL NOT be approvable, and its state
SHALL reflect that it expired rather than remaining pending forever.

An approval request left open indefinitely is not consent; treating a week-old request as live is how
"somebody approved it eventually" becomes the norm.

#### Scenario: An expired request cannot be approved
- **WHEN** an approval is attempted after the request's expiry
- **THEN** it is refused as expired, not approved
- **AND** the test FAILS if expiry is ignored

### Requirement: An approval outcome is terminal and attributed

Approving, denying or expiring SHALL be terminal: an already-resolved request SHALL NOT be re-approved or
re-denied. Every outcome SHALL record the operator responsible and the time.

#### Scenario: A resolved request cannot be resolved again
- **WHEN** an approved or denied request receives another decision
- **THEN** it is refused and the original outcome and attribution are unchanged

### Requirement: An approval names what it is for

Every approval SHALL carry a subject KIND and a subject id, so a consumer can find the approval for a
specific playbook step, response intent, or case — and so an approval for one subject can never be
mistaken for approval of another.

#### Scenario: An approval is bound to its subject
- **WHEN** an approval is recorded for one subject
- **THEN** it is retrievable by that subject kind and id, and does not satisfy a different subject

### Requirement: Automation may request an approval, but only a human may grant it

An approval request MAY be opened by automation rather than by an operator. When a playbook step requests
one, the requester SHALL be recorded as the playbook's own identity (`playbook:<name>`), never as an
operator identity, so the audit trail never attributes a machine's request to a human who did not make it.
Because no human requested it, the requester≠approver rule cannot mean *two humans*: an
automation-initiated request is a **human-in-the-loop gate** requiring exactly **one** operator approval.
This SHALL be stated wherever the control is described, so it is not mistaken for two-person integrity.

#### Scenario: A playbook step's request records the playbook as requester
- **WHEN** a `wait-for-approval` step opens a request
- **THEN** the stored requester is the playbook identity, and any operator may resolve it

#### Scenario: A subject's approval cannot satisfy another subject
- **WHEN** an approval exists for one run and step
- **THEN** it does not satisfy a different run or step — the lookup is keyed by both parts of the subject

### Requirement: The requesting feature decides what a refusal means

The approval object SHALL report the outcome (approved, denied, expired, still pending) and nothing more.
What a refusal *does* — abort, retry, escalate, proceed degraded — SHALL be decided by the requesting
feature, because the approval object cannot know the consequence of the action it gates.

#### Scenario: A denial is reported, not acted upon
- **WHEN** a request is denied
- **THEN** the approval records the denial and its approver, and the consuming feature (for a playbook, by
  failing the run) determines the effect
