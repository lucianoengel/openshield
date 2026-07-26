## ADDED Requirements

### Requirement: Materialization records which alerts contributed, idempotently

When a cross-domain incident is materialized, the system SHALL record the set of alerts that contributed
to it, and SHALL store the incident's distinct domain list. Re-materializing the same correlation SHALL
NOT duplicate the contribution records — a re-run extends the incident, so its evidence set must converge
rather than grow.

An alert may contribute to a later re-materialization of the same open incident; the record SHALL
accumulate the union, never a duplicate row for the same (incident, alert) pair.

#### Scenario: The contributing set is recorded
- **WHEN** a cross-domain incident is materialized from four alerts across three domains
- **THEN** exactly four contribution records exist for that incident, and the incident's domain list has
  three entries

#### Scenario: Re-materialization does not duplicate contributions
- **WHEN** the same correlation is materialized twice
- **THEN** the contribution record count is unchanged after the second run
- **AND** the test FAILS if the conflict-ignoring insert is dropped
