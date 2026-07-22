# audit-ledger delta

## ADDED Requirements

### Requirement: The retention purge never erases a subject under an active legal hold
The retention purge MUST NOT tombstone an entry whose subject is under an active legal hold,
regardless of the entry's retention class or age — because an entry's retention class is
immutable, a hold recorded after the entry was written is the only way to protect it. Releasing
the hold MUST restore normal purge eligibility.

#### Scenario: A legal hold overrides routine purge
- **WHEN** the purge runs over aged routine entries and one subject is under an active legal hold
- **THEN** the held subject's evidence survives while an unheld subject's is tombstoned, and releasing the hold lets a later purge tombstone it
