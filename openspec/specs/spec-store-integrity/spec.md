# spec-store-integrity Specification

## Purpose

The spec store's own contract. Every requirement an archived change introduced remains present in its
capability file, and a repeatable procedure recovers any that go missing — because 170 of 526 had already
gone missing before this was written, through an archive step that skipped the sync and a sync that
overwrote the capability file with the delta being merged into it. Both report success, which is why the
guard is automatic rather than a matter of the archiver's diligence.

## Requirements

### Requirement: An archived change's requirements remain in its capability spec

Every requirement heading introduced by an archived change SHALL be present in that change's capability
spec file.

The archive is the project's record of what was proposed, reviewed and shipped. A capability file that
has lost a requirement does not read as incomplete — it reads as a capability nobody asked for, which is
how a shipped guarantee comes to be redesigned by the next person to open the file. Because a delta is
written and validated against whatever the capability file currently says, a loss also propagates into
every change made afterwards.

This SHALL be enforced automatically rather than by the archiver's diligence: the loss this requirement
exists to prevent has already happened at scale, through both an explicit "archive without syncing" and a
sync that REPLACED a capability file with the delta being merged into it. Neither was noticed, because
neither produces a failure.

#### Scenario: A requirement present in an archived delta is present in its capability file

- **WHEN** the spec-store check runs over every archived change
- **THEN** it reports no requirement header that is absent from the corresponding capability file

#### Scenario: A capability file that lost a requirement fails the check

- **WHEN** a capability file does not contain a requirement header that an archived delta introduced
- **THEN** the check fails, naming the capability, the requirement and the archived change it came from

#### Scenario: A capability file with no archived history is not flagged

- **WHEN** a capability file contains requirements that no archived change introduced
- **THEN** the check does not fail, because a capability may legitimately carry requirements authored
  outside the archive

### Requirement: The reconstruction is mechanical and re-runnable

Recovering a capability file from its archived deltas SHALL be performed by a repeatable procedure that
replays deltas in chronological order, not by hand-editing. Its result SHALL be reproducible from the
archive alone, so the reconstruction can be re-run, reviewed as a diff, and audited by the same check
that measures the gap.

A `## MODIFIED Requirements` entry SHALL supersede the earlier requirement of the same name; a
`## ADDED Requirements` entry SHALL introduce one. A delta section the procedure has not been taught to
interpret SHALL cause it to FAIL rather than skip that section — silently dropping an unrecognised
section is the precise failure being repaired.

#### Scenario: A later modification supersedes the requirement it revises

- **WHEN** one archived change ADDs a requirement and a later archived change MODIFIEs it
- **THEN** the capability file carries the later version, once

#### Scenario: An unrecognised delta section stops the replay

- **WHEN** an archived delta contains a section type the replay does not handle
- **THEN** the replay fails and names the section and the change, rather than continuing

#### Scenario: Capabilities that were never damaged are left alone

- **WHEN** the reconstruction runs against a capability whose file already contains every archived
  requirement
- **THEN** that file is unchanged

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

