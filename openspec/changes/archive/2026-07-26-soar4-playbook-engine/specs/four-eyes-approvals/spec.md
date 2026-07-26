## ADDED Requirements

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
