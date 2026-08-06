# audit-timeline

## ADDED Requirements

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
