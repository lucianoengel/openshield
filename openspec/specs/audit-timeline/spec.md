# audit-timeline Specification

## Purpose
The `openshieldctl` read surface over the audit ledger: reconstruct an incident as an ordered
timeline and verify the chain, always reporting verification state alongside the data and never
claiming trust — operator identity, viewer accountability, completeness — that it does not have.
## Requirements
### Requirement: The timeline reconstructs an incident in order
The CLI MUST render audit entries as a timeline ordered by sequence, filterable by subject, time
range and event, over the persisted ledger.

This replaces the investigation UI cut from Phase 1 (D12 context). The value is reconstruction:
an operator asks "what happened around this subject at this time" and receives the entries in
the order they were recorded.

#### Scenario: A seeded incident renders as an ordered timeline
- **WHEN** entries for a subject are written and `openshieldctl timeline --subject S` is run
- **THEN** those entries print in ascending sequence order
- **AND** entries for other subjects are excluded

#### Scenario: Time and event filters narrow the timeline
- **WHEN** `--since`, `--until` or an event filter is supplied
- **THEN** only entries within the range and matching the filter are rendered

### Requirement: The timeline states its verification result before its rows
The CLI MUST verify the chain before rendering and MUST print the verification state — consistency,
validated range, completeness, and which anchor mode ran — ahead of the timeline rows.

A tool that prints a plausible incident record without saying whether the record is intact
launders unverified rows into evidence. The verification state is not a separate concern from the
timeline; it is the first thing the timeline says.

#### Scenario: A consistent chain is reported as such, with completeness caveated
- **WHEN** the timeline is rendered over an untampered chain with no external anchor
- **THEN** the header states the chain is consistent and that completeness is unverified
- **AND** the header names whether an anchor was supplied

#### Scenario: A broken chain is named, not hidden
- **WHEN** the timeline is rendered over a chain tampered at sequence N
- **THEN** the header reports inconsistency and names N as the first break
- **AND** rows from N onward are marked as affected
- **AND** the broken tail is still printed, because an operator investigating tampering must see
  the tampered data

### Requirement: Verification is available as a scriptable check with meaningful exit codes
The CLI MUST offer verification alone, exiting non-zero when the chain is inconsistent or the
ledger is unavailable, so a scheduled job can act on the result without parsing output.

Tamper detection that only a human reading formatted output can notice is not operational. The
exit code is the contract a cron job or CI step consumes.

#### Scenario: Exit codes distinguish the outcomes a scheduler must tell apart
- **WHEN** `openshieldctl verify` runs against a consistent chain
- **THEN** it exits 0
- **WHEN** it runs against a tampered chain
- **THEN** it exits with a distinct non-zero code for inconsistency
- **WHEN** the database is unreachable
- **THEN** it exits with a distinct non-zero code for unavailability, not the inconsistency code,
  because "cannot tell" and "tampered" demand different operator responses

### Requirement: The CLI does not overstate the trust it provides
The CLI MUST NOT imply operator accountability, authorisation, or completeness it does not have.
Anchor material exported from the host is labelled with the limit of what it attests.

Until identity (T-017) and external anchoring (T-019) exist, the CLI runs for anyone who can
reach the database, records no accountable viewer, and cannot prove nothing was removed. Saying
so on the surface is the honest posture; a reassuring silence is the failure mode this project
was built to avoid.

#### Scenario: Anchor export states what it does and does not prove
- **WHEN** the current anchor is exported
- **THEN** the output states that an anchor captured from a host that could later be compromised
  is only meaningful if captured while the host is trusted
- **AND** it does not describe the exported file as independent proof

#### Scenario: No surface claims a viewer was recorded
- **WHEN** the CLI reads an investigation
- **THEN** it writes no audit entry implying an identified viewer, because no identity exists to
  record and an unattributable "viewed" entry would misrepresent D20 accountability as present

