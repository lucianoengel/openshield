## ADDED Requirements

### Requirement: An engaged emergency disable downgrades enforcement to observation

While the emergency disable is engaged, a Decision carrying an enforcing action SHALL NOT reach any
enforcer. It SHALL be recorded as observed instead. One implementation SHALL serve every enforcement call
site, so no path can be left enforcing while the switch is engaged.

#### Scenario: An enforcing decision is not enforced
- **WHEN** the switch is engaged and a decision would block, deny or quarantine
- **THEN** no enforcer is invoked for it

#### Scenario: A non-enforcing decision is unaffected
- **WHEN** the switch is engaged and a decision only alerts
- **THEN** its handling is unchanged

#### Scenario: Disengaging restores enforcement
- **WHEN** the switch is disengaged
- **THEN** subsequent enforcing decisions reach their enforcers again

### Requirement: Detection and audit continue while enforcement is disabled

Engaging the switch SHALL NOT stop classification, decision-making or the audit trail. The record of what
would have been enforced is what an operator needs afterwards, and a switch that also stops the trail is a
blindfold rather than a safety control.

#### Scenario: The ledger still records the decision
- **WHEN** an enforcing decision is suppressed
- **THEN** the decision is still recorded

### Requirement: Every suppression is recorded, and so is the switch itself

Each suppressed enforcement SHALL be recorded individually, and engaging or disengaging the switch SHALL
itself be recorded with its reason and source. A silent kill switch is indistinguishable from a product
that has stopped working.

#### Scenario: A suppression is counted and attributable
- **WHEN** enforcement is suppressed
- **THEN** the occurrence is counted and reports the reason the switch is engaged

#### Scenario: Engaging is recorded
- **WHEN** the switch is engaged
- **THEN** the reason and the source that engaged it are recorded

### Requirement: The switch must be affirmatively engaged

If the switch's state cannot be determined, enforcement SHALL continue and the failure SHALL be reported.
A read error, a missing file or an unreachable store MUST NOT disable enforcement.

#### Scenario: An unreadable source does not disable enforcement
- **WHEN** the switch's source cannot be read
- **THEN** enforcement continues and the error is reported

#### Scenario: Absence is not engagement
- **WHEN** no break-glass file exists and no setting is present
- **THEN** enforcement continues
