## ADDED Requirements

### Requirement: Decisions record the enrichment context version
`Decision` MUST carry a `context_version` identifying the enrichment Context it was evaluated
against, empty when no Context applied.

Replay cannot reproduce a Decision without it: re-running an Event against today's context would
legitimately produce a different answer, and an audit trail whose entries cannot be reproduced
is not evidentiary. The field was added before any consumer existed because retrofitting one
into a hash-chained ledger means a migration and a break in chain continuity.

#### Scenario: Replay compares the context version
- **WHEN** a recorded Decision is replayed
- **THEN** the comparison includes `context_version`
- **AND** replaying against a different context version is reported as divergence rather than
  silently accepted

#### Scenario: Phase 1 records an empty context version
- **WHEN** a Decision is produced with no Context present
- **THEN** `context_version` is empty rather than absent-and-defaulted
