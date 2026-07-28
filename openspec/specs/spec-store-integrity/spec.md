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
