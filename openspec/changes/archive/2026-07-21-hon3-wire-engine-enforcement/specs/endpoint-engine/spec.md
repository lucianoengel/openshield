# endpoint-engine delta

## ADDED Requirements

### Requirement: The engine binary registers file enforcers opt-in, observe-only by default
The engine binary MUST register its file enforcers only when enforcement is explicitly
enabled, and MUST remain observe-only by default — with enforcement off, a decision is
recorded but no file is touched. With enforcement on, a quarantine decision MUST move the
flagged file and audit the enforcement outcome; an encrypt enforcer MUST be registered when a
key is configured.

#### Scenario: Enforcement is opt-in and contains a flagged file
- **WHEN** the engine processes a flagged file with enforcement enabled, and separately with it disabled
- **THEN** enabled it quarantines the file and audits an enforced outcome, and disabled it leaves the file untouched
