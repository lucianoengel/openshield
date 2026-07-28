## REMOVED Requirements

### Requirement: Phase 1 records decisions without acting on them

**Reason**: The requirement is a Phase-1 statement that was never retired. It requires that the pipeline
"SHALL NOT invoke any enforcer" and asserts that a BLOCK decision leaves the underlying operation
"unimpeded". Enforcers have existed since M2 and run whenever they are enabled, so the requirement now
contradicts the product it describes.

**Migration**: Replaced by "Recording is unconditional; acting is opt-in", which is the durable rule the
Phase-1 statement was a temporary instance of. The observe-only DEFAULT (D1) survives intact; what is
dropped is the claim that enforcement cannot happen at all.

## ADDED Requirements

### Requirement: Recording is unconditional; acting is opt-in

Every Decision SHALL be recorded to the audit path whether or not it is acted upon, and enforcement
SHALL be OFF unless it has been explicitly enabled. A deployment that has not opted in SHALL behave
exactly as an observing one: the Decision is written, no enforcer runs, and the underlying operation
proceeds.

The asymmetry is deliberate. Recording is what the audit trail is for and must never depend on
configuration, or a gap in the record would mean "nothing happened" and "enforcement was off" at the
same time. Acting is the half that can break a machine, so it is the half that must be asked for.

#### Scenario: A blocking decision in an observing deployment is recorded, not executed

- **WHEN** policy evaluation produces an enforcing action and enforcement has not been enabled
- **THEN** the Decision is written to the audit path
- **AND** no enforcer is invoked
- **AND** the underlying operation proceeds

#### Scenario: The same decision with enforcement enabled is both recorded and carried out

- **WHEN** policy evaluation produces an enforcing action and enforcement has been enabled
- **THEN** the Decision is written to the audit path BEFORE the enforcer runs
- **AND** the enforcement outcome is audited

#### Scenario: Recording does not depend on the enforcement setting

- **WHEN** the same event is decided in an observing deployment and in an enforcing one
- **THEN** both write a Decision, and the records are distinguishable only by the enforcement outcome
