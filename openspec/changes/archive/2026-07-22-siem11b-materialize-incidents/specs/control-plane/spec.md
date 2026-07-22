# control-plane (delta)

## ADDED Requirements

### Requirement: Correlated incidents are materialized with identity and state
The control plane MUST persist a correlated incident with a stable id and a lifecycle state, with at
most one open incident per subject: re-running correlation MUST update the subject's open incident
(refreshing its counts and span) rather than duplicating it, and MUST leave an acknowledged incident
unchanged so a later burst opens a new incident. An operator MUST be able to acknowledge an incident
as a unit — first-acknowledgement-wins, a non-existent incident is an error, and a database failure
during acknowledgement MUST propagate rather than read as not-found. The incident acknowledgement
surface MUST be operator-gated and mutating.

#### Scenario: An incident is materialized once per subject and acknowledged as a unit
- **WHEN** correlation is materialized for a bursting subject, re-materialized after another alert, and then the incident is acknowledged
- **THEN** exactly one open incident exists for the subject and is refreshed (not duplicated) on re-materialization, the acknowledgement is first-wins and moves it out of the open state, and a later burst opens a new open incident while the acknowledged one remains
