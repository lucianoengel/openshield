# control-plane delta

## ADDED Requirements

### Requirement: A correlated incident can open a pre-populated investigation case
The control plane MUST be able to open an investigation case for a correlated incident's
subject, writing an opening note that summarizes the incident (alert count, peak risk, time
span) in the same transaction, attributed to the correlation system rather than an operator.
An incident without a subject MUST NOT open a case.

#### Scenario: An incident opens a case with its summary
- **WHEN** an operator opens a case from a correlated incident
- **THEN** a case is created for the incident's subject with a system-authored note carrying the alert count and peak risk, and a subjectless incident opens no case
