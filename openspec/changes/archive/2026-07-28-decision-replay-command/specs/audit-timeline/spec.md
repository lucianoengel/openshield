# audit-timeline

## ADDED Requirements

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
