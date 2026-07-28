## ADDED Requirements

### Requirement: A removed or renamed requirement is not reported as lost

The spec-store check SHALL treat a requirement withdrawn by a later archived change as legitimately
absent, and SHALL follow a rename to its new heading. Only a requirement that is still in force and yet
missing from its capability file counts as a loss.

Without this the check makes removal impossible: a requirement the project has deliberately retired stays
in an archived delta forever, so the guard demands its presence forever, and the only way to retire
anything is to disable the guard. A check that must be switched off to do ordinary work does not survive.

The tools SHALL continue to REFUSE a delta section they do not understand rather than skipping it.
Refusing is what forced these two sections to be implemented instead of silently dropped, which is the
behaviour that lost 170 requirements in the first place.

#### Scenario: A requirement removed by a later change is not reported missing

- **WHEN** one archived change adds a requirement and a later archived change removes it, and the
  capability file does not contain it
- **THEN** the check reports no loss for that requirement

#### Scenario: A requirement removed and then re-added is required again

- **WHEN** a requirement is removed by one change and added again by a later one, and the capability file
  does not contain it
- **THEN** the check reports it as missing

#### Scenario: A renamed requirement is followed to its new heading

- **WHEN** an archived change renames a requirement and the capability file contains only the new heading
- **THEN** the check reports no loss

#### Scenario: An unrecognized delta section still stops the tools

- **WHEN** a delta contains a section type the tools do not implement
- **THEN** they fail and name it, rather than ignoring that section
