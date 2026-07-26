## ADDED Requirements

### Requirement: The documented component set matches the binaries that exist

The operator documentation SHALL name every command the project ships, and SHALL NOT name one that does
not exist. This SHALL be enforced by test in both directions. A runbook is read under pressure, and one
that omits a component or names a removed one costs an operator time exactly when they have none.

#### Scenario: An undocumented binary fails the check
- **WHEN** a command exists that the runbook does not name
- **THEN** the check fails, naming it

#### Scenario: A documented binary that no longer exists fails the check
- **WHEN** the runbook names a command that is not present
- **THEN** the check fails, naming it
