# control-plane delta

## ADDED Requirements

### Requirement: The operator can search fleet peer alerts by filter, with input bound as data
The control plane MUST let an operator search peer alerts filtered by subject, minimum risk,
and time window, returning matching alerts newest first. The filter MUST be applied as
parameterized SQL — operator-supplied values MUST be bound as query parameters, never
concatenated into the statement — so a search cannot alter or damage the store. The search
endpoint MUST sit behind the operator-role gate; a non-operator MUST be refused.

#### Scenario: A filtered search returns matching alerts and resists injection
- **WHEN** an operator searches peer alerts with subject, risk, or time filters
- **THEN** only matching alerts are returned, an injection-shaped value matches nothing and leaves the store intact, and a non-operator is refused
