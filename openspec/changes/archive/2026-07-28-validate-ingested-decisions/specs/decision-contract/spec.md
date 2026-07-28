# decision-contract

## ADDED Requirements

### Requirement: A decision received from an agent MUST be validated before it is reasoned about

The control plane MUST validate a decision received as telemetry against the decision contract —
a known action, a present confidence within range, and an identifying policy — before projecting it
into the alert stream, and MUST NOT project one that fails.

Signature verification establishes WHO sent a decision, not that what they sent is expressible in the
platform's contract. An enrolled agent that is compromised, or merely version-skewed, can otherwise
place values in the correlation stream that the severity mapping was never designed to consider.

#### Scenario: An out-of-range confidence does not become an alert

- **WHEN** a verified decision carries a confidence outside the valid range
- **THEN** no alert may be projected from it
- **AND** in particular no CRITICAL alert

#### Scenario: An action outside the closed set is not projected

- **WHEN** a verified decision carries an action the closed set does not contain
- **THEN** no alert may be projected from it

#### Scenario: A well-formed decision is still projected

- **WHEN** a verified, well-formed decision with an alertable action is received
- **THEN** an alert MUST be projected

### Requirement: A refused decision MUST be retained and counted

A decision refused by contract validation MUST still be retained as telemetry, MUST be counted, and
the count MUST be observable.

A malformed decision arriving is itself evidence — the signal an investigator wants after learning an
agent was compromised — so refusing to reason about it must not mean destroying it.

#### Scenario: The refusal is counted and the payload kept

- **WHEN** a decision fails contract validation
- **THEN** it MUST remain queryable as telemetry
- **AND** the refusal MUST increment an observable counter
