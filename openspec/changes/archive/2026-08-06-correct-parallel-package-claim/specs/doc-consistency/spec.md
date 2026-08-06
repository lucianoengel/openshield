# doc-consistency

## ADDED Requirements

### Requirement: A recorded cause states whether it was reproduced

Where a decision record or design note asserts WHY something failed, it SHALL either have been reproduced,
or say plainly that it was not.

This register's value is that its causal claims can be relied on. A mechanism that was inferred from a
single observation and never checked reads identically to one that was proven, and the next person either
works around a hazard that does not exist or spends time chasing it. Recording "observed, cause unknown"
costs a sentence; an unreproduced mechanism costs whoever believes it.

The failure is specific and has happened: an archived design note asserted that two test packages raced on
shared tables, when both already hold the same advisory lock for their process lifetime and the command
passes. One run had genuinely failed; the explanation attached to it had not been checked.

#### Scenario: An unreproduced cause is labelled
- **WHEN** a record states why something failed and the failure was not reproduced
- **THEN** the record says so, rather than presenting the mechanism as established

#### Scenario: A withdrawn explanation keeps its observation
- **WHEN** a recorded cause is found not to hold
- **THEN** the correction withdraws the mechanism and preserves the observation, rather than deleting both
