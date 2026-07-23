# file-integrity-monitoring Specification

## Purpose
Detect TAMPERING of operator-designated critical files (config, binaries, audit rules) by comparing
them against a persistent, known-good SHA-256 baseline, and turn each drift into an auditable pipeline
decision. It keys on a CONTENT hash — so a modification that preserves size and modification time
(timestomping) is still caught — detects DELETION of a baseline file, and persists its baseline so it
answers "has this drifted from its approved state" across restarts, not merely "changed since I started
watching". Hashing runs with the caller's own credentials (no privilege); real-time kernel watch, a
signed tamper-evident baseline, and permission/ownership monitoring are follow-ups.

## Requirements
### Requirement: Cryptographic baseline drift detection

The system SHALL detect drift of operator-designated critical files from a persistent known-good
baseline that records each file's SHA-256 content hash and size. A scan SHALL report a file as MODIFIED
when its current content hash differs from the baseline — EVEN IF its modification time and size are
unchanged — as ADDED when a file present now was not in the baseline, and as DELETED when a baseline
file is now missing. A file whose content, and therefore hash, is unchanged SHALL produce no drift. The
scan SHALL be bounded: a per-file size cap limits how much of a file is hashed, and a file exceeding the
cap SHALL be flagged rather than silently omitted (a silent skip would read as "verified, unchanged").

#### Scenario: A content change with preserved timestamp and size is detected
- **WHEN** a baseline file's content is changed but its modification time and size are restored to the original
- **THEN** the scan reports the file as modified, because the content hash differs

#### Scenario: A deleted baseline file is detected
- **WHEN** a file recorded in the baseline is removed
- **THEN** the scan reports the file as deleted

#### Scenario: A new file in a watched location is detected
- **WHEN** a file not in the baseline appears in a watched path
- **THEN** the scan reports the file as added

#### Scenario: An unchanged baseline produces no drift
- **WHEN** no watched file has changed since the baseline
- **THEN** the scan reports no drift

### Requirement: The baseline is persistent across restarts

The system SHALL persist the baseline manifest so the known-good state survives a restart and can be
reviewed/approved by an operator. Saving then loading the manifest SHALL round-trip without changing the
recorded hashes, and a scan against a loaded manifest SHALL behave identically to a scan against the
in-memory baseline it was saved from. The baseline manifest in this increment is a plain file and is NOT
tamper-evident; an operator with write access to it can alter the known-good state — this limitation
MUST be documented and surfaced.

#### Scenario: A saved baseline loads and scans identically
- **WHEN** a baseline is saved to disk and loaded into a fresh manifest
- **THEN** the loaded manifest carries the same hashes and a scan against it detects the same drift as the original

### Requirement: A file-integrity drift enters the pipeline as an auditable event

The system SHALL emit each detected drift as a content-free event into the detection pipeline, carrying
the file's path but never its content, so a policy can decide (for example, alert) on a tampered or
deleted critical file and the decision is audited. A deleted-file event carries no content to inspect
and MUST reach the policy on its metadata rather than failing because the file cannot be opened. The
integrity monitor MUST be inert when no baseline is configured, and MUST NOT itself decide the response
— the policy decides, on the event.

#### Scenario: A drift becomes a policy decision
- **WHEN** a watched critical file is modified or deleted and the integrity monitor scans
- **THEN** a corresponding content-free file event flows the pipeline to the policy, which can alert, and the outcome is audited

#### Scenario: A deletion reaches the policy without a classify failure
- **WHEN** a deleted-file drift event is processed
- **THEN** it is classified as metadata-only (no attempt to open the missing file) and the policy still evaluates it
