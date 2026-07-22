# audit-ledger delta

## ADDED Requirements

### Requirement: The application runs under a non-owner role that cannot weaken the append-only guard
The ledger MUST support running the application under a non-owner database role that can insert
entries and perform the permitted tombstone update but CANNOT alter the table, disable the
append-only trigger, delete, drop the table, or escalate to the owner. Migrations MUST be an
owner operation; the application MUST be able to open an already-migrated database without owner
rights, skipping migration via a read-only check.

#### Scenario: A non-owner app can append but cannot weaken the guard
- **WHEN** the application runs under a non-owner writer role
- **THEN** it can append entries but cannot disable the append-only trigger, delete, drop the table, or become the owner
