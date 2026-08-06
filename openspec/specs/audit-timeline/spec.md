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

### Requirement: A recorded decision MUST be replayable against a supplied event

The operator CLI MUST accept an event and report whether re-evaluating it reproduces the decision the
ledger recorded for that event, comparing the same explicit field set the replay contract defines.

A ledger that can be verified but whose decisions cannot be reproduced supports only half of the
platform's claim: it establishes that a record was not altered, not that the record follows from the
inputs and the policy.

#### Scenario: An unchanged policy reproduces a recorded decision

- **WHEN** an event whose decision is recorded in the ledger is replayed against the same policy
- **THEN** the command MUST report the decision as reproduced, and exit zero

#### Scenario: A changed policy is reported as a divergence

- **WHEN** the same event is replayed against a policy that decides differently
- **THEN** the command MUST report a divergence, naming the field that differs
- **AND** MUST exit non-zero, so a policy change can be gated on it

#### Scenario: An unrecorded event is not a divergence

- **WHEN** an event is replayed whose id matches no ledger entry
- **THEN** the command MUST report that no decision is recorded, distinctly from a divergence

#### Scenario: An ambiguous event id is refused

- **WHEN** an event id matches more than one ledger entry
- **THEN** the command MUST refuse rather than compare against one of them

### Requirement: A replay report MUST state that the input may have changed

A divergence report MUST state that the difference can arise from the input having changed as well as
from the policy having changed.

The ledger stores no content, so a replay re-reads whatever the event points at now. An operator who
reads a divergence as proof of a policy regression, and reverts a policy over a file that someone
edited, has been misled by a report that was technically accurate.

#### Scenario: A divergence names both possible causes

- **WHEN** a replay diverges
- **THEN** the report MUST name both the policy and the input as possible causes
<!-- synced from decision-replay-command -->

### Requirement: The replay answer has exactly one implementation

The comparison between a recorded decision and a re-evaluation SHALL be computed in one place, and every
surface that reports it SHALL render that result rather than recompute it.

Replay's value is being the same answer wherever it is asked. An operator who receives one verdict from
one surface and a different verdict from another has learned only that the product cannot be trusted about
reproducibility, which is the property replay exists to demonstrate.

#### Scenario: A second surface renders rather than recomputes
- **WHEN** a surface other than the command line reports a replay
- **THEN** it reports the result of the single comparison

### Requirement: A replay result carries its own limit

The result SHALL carry the statement of what it does and does not establish, so a surface cannot report
the verdict without it.

The ledger keeps no content, so a reproduction establishes only that the policy produces the recorded
decision from the supplied input, and a divergence may mean the input changed rather than the policy. A
renderer that omitted this would turn a hedged answer into a confident one.

#### Scenario: Both a reproduction and a divergence state their limit
- **WHEN** a replay result is produced with either outcome
- **THEN** it carries the limit on what that outcome establishes

### Requirement: An unavailable comparison is not reported as a divergence

Where the comparison cannot be made, the result SHALL say so as a distinct outcome.

Collapsing it into divergence lets a mistyped event id read as a policy regression, and those call for
opposite responses.

#### Scenario: No recorded decision is distinguishable from a changed one
- **WHEN** no ledger entry records a decision for the supplied event
- **THEN** the result reports that the comparison could not be made, not that the policy diverged

<!-- from replay-answer-one-implementation -->
