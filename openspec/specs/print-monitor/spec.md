# print-monitor Specification

## Purpose
Deciding a PRINT job before it prints (DLP-2b). The spooler's filter chain is the interposition point — a
filter's non-zero exit aborts the job — so print control is prevention rather than reporting, without any
driver or injection. The filter parses nothing: the document is classified in the sandboxed worker, the
event carries metadata only (not even the title, which is often the sensitive fact itself), and an
unavailable engine prints the job loudly rather than stopping an office from working.

## Requirements

### Requirement: A print job is intercepted in the spooler chain and decided before it prints

The system SHALL intercept a print job inside the spooler's filter chain, obtain a policy decision for it,
and either pass the job through unchanged or ABORT it. An aborted job SHALL NOT reach the printer.

The intercepting filter SHALL NOT parse the job itself: the content SHALL be classified in the sandboxed
worker, so a malformed document cannot execute code inside the print path (D71/D29).

#### Scenario: A denied job never prints
- **WHEN** policy denies a job containing sensitive content
- **THEN** the filter exits non-zero and emits no job data, so the spooler aborts the job
- **AND** the test FAILS if the job data is written out regardless of the decision

#### Scenario: An allowed job is passed through byte-for-byte
- **WHEN** policy allows a job
- **THEN** the job data written out is identical to the data read in
- **AND** the test FAILS if the filter alters the job

### Requirement: The print event carries metadata, never the document

A print job SHALL produce a content-free event carrying job metadata — the printer, the submitting user,
the job size — and SHALL NOT carry the document's content. The content SHALL reach only the sandboxed
classifier.

#### Scenario: The event carries no document content
- **WHEN** a job containing recognizable sensitive text is intercepted
- **THEN** the serialized event contains none of that text
- **AND** the classification for that job reports the corresponding detector

### Requirement: A print job is an exfiltration channel

The exfil channel model SHALL include print, and a print event SHALL be tagged with it when policy input is
built, so a channel-aware policy gates printing with the same rule shape it uses for other channels.

#### Scenario: Policy input carries the print channel
- **WHEN** policy input is built for a print event
- **THEN** its exfil channel is the print channel

### Requirement: An unavailable engine must not stop printing

If the engine is unreachable, slow, or fails, the job SHALL PRINT and the fail-open SHALL be recorded at
high severity. The filter SHALL NOT abort a job because the decision path failed.

A DLP that stops an office printing because a daemon died is a DLP that gets uninstalled; availability over
enforcement is the same deliberate trade as the exec gate and the egress proxy (D17/D73), and the loud
audit is what keeps it honest rather than silent.

#### Scenario: A dead engine still prints
- **WHEN** the verdict path is unavailable
- **THEN** the job passes through unchanged and the fail-open is audited
- **AND** the test FAILS if the filter aborts the job when it cannot get a decision
