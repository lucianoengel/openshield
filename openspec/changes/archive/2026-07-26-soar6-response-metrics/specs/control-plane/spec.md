## ADDED Requirements

### Requirement: The first move off `open` records the acknowledgement

Any transition that takes an incident out of the `open` state SHALL record the acknowledging operator and
time if they are not already recorded, regardless of which route made the move. Recording it only on the
dedicated acknowledge path meant an operator who triaged an incident directly erased their own response
time — the incident could never be measured for time-to-acknowledge, which is the outcome the forward-only
lifecycle exists to prevent.

The stamp SHALL NOT overwrite an existing acknowledgement: first-ack-wins attribution is preserved, so the
recorded acknowledger stays the operator who actually got there first.

#### Scenario: Transitioning straight to triaged records the acknowledgement
- **WHEN** an operator transitions an incident from `open` to `triaged`
- **THEN** the acknowledging operator and time are recorded as that operator and that moment

#### Scenario: A later transition does not overwrite an earlier acknowledgement
- **WHEN** an incident is acknowledged by one operator and later transitioned by another
- **THEN** the recorded acknowledger and time are unchanged

#### Scenario: A refused transition records nothing
- **WHEN** a transition is refused as backward
- **THEN** no acknowledgement is recorded
