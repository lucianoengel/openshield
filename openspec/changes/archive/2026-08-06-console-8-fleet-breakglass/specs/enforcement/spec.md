# enforcement

## ADDED Requirements

### Requirement: Every published fleet control is recorded

A fleet control that reaches the wire SHALL have been recorded first, carrying its id, verb, sequence,
issue time, expiry and reason. Recording SHALL happen after the four-eyes gate and before publication, and
a failure to record SHALL prevent publication.

Without this the most consequential message the product sends leaves no durable trace of itself: the
issue time, expiry and reason exist only on the wire, and an operator who finds enforcement suppressed can
recover none of them.

#### Scenario: A refused control is not recorded
- **WHEN** a disable is published without an approved four-eyes approval
- **THEN** publication is refused and no record of the control exists

#### Scenario: A control that cannot be recorded is not sent
- **WHEN** the record cannot be written
- **THEN** the control is not published

#### Scenario: The record carries the control's own expiry
- **WHEN** a control is published with a time-to-live
- **THEN** the recorded expiry is the one the fleet received, not one recomputed at read time

### Requirement: Current fleet suppression is derived, never stored

Whether enforcement is currently suppressed fleet-wide SHALL be derived from the recorded controls, as the
highest-sequence control whose expiry has not lapsed being a disable. No stored flag SHALL assert
suppression.

A stored flag needs a writer to end suppression when a time-to-live lapses, and a writer that falls behind
makes the operator surface disagree with the fleet in the one direction that matters — reporting
protection as present when it is not, or absent when it is.

#### Scenario: A lapsed time-to-live ends suppression with no writer
- **WHEN** the only disable's expiry has passed
- **THEN** the fleet is not reported as suppressed

#### Scenario: A later restore supersedes an earlier disable
- **WHEN** a restore is published at a higher sequence than a standing disable
- **THEN** the fleet is not reported as suppressed

#### Scenario: Ordering follows sequence, not wall-clock time
- **WHEN** a later-sequenced control carries an earlier issue time than its predecessor
- **THEN** the sequence decides which control stands, matching how consumers order them

### Requirement: The break-glass register names the two people who authorized suppression

The record of a fleet disable SHALL be readable together with the requester, approver and assurance level
of the four-eyes approval that authorized it. Where an approval does not exist — a restore is not gated —
its absence SHALL be reported as absent rather than as an empty identity.

The publishing path is an operator-local command with no authenticated principal in scope, so an
`issued_by` recorded there would name an identity nothing verified. The approval pair is the identity that
was verified, and it is the answer to who suppressed enforcement.

#### Scenario: A disable reports its four-eyes pair
- **WHEN** a recorded disable is read back
- **THEN** the requester and approver from its approval are reported

#### Scenario: A restore reports no pair rather than an empty one
- **WHEN** a recorded restore is read back
- **THEN** the absence of an approval is reported as absent
