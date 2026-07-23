## ADDED Requirements

### Requirement: A DENY_EXEC decision inline-blocks an exec

The system SHALL answer an exec-permission event by DENYING the execution to the kernel if and only if
the pipeline decides DENY_EXEC for that exec; every other decision SHALL allow it. The decision path
SHALL remain under the watchdog's hard fail-open budget, so a slow or failing evaluation allows the exec
(inline prevention never becomes a denial of service).

#### Scenario: A denied exec is blocked
- **WHEN** the pipeline decides DENY_EXEC for an exec-permission event
- **THEN** the kernel is answered DENY (the exec is refused inline)

#### Scenario: A permitted exec runs
- **WHEN** the pipeline decides anything other than DENY_EXEC
- **THEN** the kernel is answered ALLOW

#### Scenario: A slow or failing evaluation fails open
- **WHEN** the exec decision exceeds the budget or errors
- **THEN** the kernel is answered ALLOW (fail-open) and the outcome is audited high-severity
