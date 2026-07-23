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

### Requirement: File-integrity drift is detected in real time

The system SHALL detect a change to a watched critical file in real time, without waiting for the
periodic scan, by watching the critical paths for change events and triggering an immediate baseline
re-check when one occurs. The change event MUST only trigger the re-check; the drift itself MUST still be
computed by the cryptographic baseline scan, so a modification is confirmed by a content-hash difference
(a timestomped edit is caught, a change that does not alter content yields no drift). The real-time watch
SHALL be additive to the periodic scan, which remains the completeness backstop, and SHALL be
best-effort: if the watch cannot be established, the system MUST log and continue with the periodic scan
rather than fail.

#### Scenario: A modified critical file is detected without waiting for the poll
- **WHEN** a watched critical file's content is changed
- **THEN** a drift event is produced well within the periodic scan interval, triggered by the change

#### Scenario: A benign change that does not alter content produces no drift
- **WHEN** a watched file receives a change event but its content (hash) is unchanged
- **THEN** no drift is produced (the baseline scan confirms it, not the raw event)

#### Scenario: An unavailable watch degrades to the periodic scan
- **WHEN** the real-time watch cannot be established
- **THEN** the condition is logged and file-integrity monitoring continues via the periodic scan

### Requirement: The baseline can be operator-signed and verified before it is trusted

The system SHALL support an operator-signed baseline: the operator signs the baseline manifest with a
private key, and a node configured with the corresponding trusted public key MUST verify the signature
before trusting the manifest. Verification MUST be fail-closed — a malformed envelope, a missing or
invalid signature, or a signature from a different key MUST be refused and MUST yield no manifest — and
MUST happen before the manifest is used. The signature MUST be domain-separated so a signature minted for
the baseline cannot validate for any other purpose in the system, and vice-versa. The node MUST hold only
the public key; it MUST NOT sign its own baseline.

#### Scenario: A validly-signed baseline is accepted
- **WHEN** a baseline signed by the operator key is loaded with the matching trusted public key
- **THEN** the manifest is accepted and used

#### Scenario: A tampered signed baseline is refused
- **WHEN** a signed baseline's manifest bytes are altered after signing, or its signature is from a different key
- **THEN** verification fails and the manifest is refused (no manifest is returned)

### Requirement: Verification is required when a trusted key is configured

When a trusted operator public key is configured, the system MUST load the baseline only via signature
verification: an unsigned or unverifiable baseline MUST be a fatal configuration error, and the node MUST
NOT capture and trust its own baseline. When no trusted key is configured, the system MAY load an
unsigned baseline for backward compatibility, but MUST loudly warn that an unsigned baseline is
tamper-vulnerable.

#### Scenario: An unsigned baseline is refused when a key is required
- **WHEN** a trusted public key is configured but the baseline is unsigned or does not verify
- **THEN** the system refuses to run on that baseline (a fatal configuration error)

#### Scenario: The unsigned path is warned when no key is configured
- **WHEN** no trusted public key is configured and an unsigned baseline is loaded
- **THEN** the load proceeds but a warning states that the unsigned baseline is tamper-vulnerable
