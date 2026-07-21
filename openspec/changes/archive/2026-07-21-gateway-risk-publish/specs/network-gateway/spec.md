# network-gateway delta

## ADDED Requirements

### Requirement: The gateway populates its risk store from published risk updates
The gateway MUST subscribe to published risk updates and record each into its risk store, so continuous
verification decides on real risk. Applying an update MUST record the subject's latest risk.

#### Scenario: A published risk update reaches the risk store
- **WHEN** the gateway applies a risk update for a subject
- **THEN** the risk store returns that subject's risk
