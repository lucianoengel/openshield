# packaging (delta)

## ADDED Requirements

### Requirement: The running product connects to the ledger DB as a non-owner role
The shipped deployment configuration MUST run the long-running binaries under a NON-OWNER database
role that can perform the application's writes (append the ledger, write the aggregate tables) but
cannot ALTER the schema or disable the append-only trigger, so the database-level append-only
boundary is not owner-bypassable in the running product. Schema migration MUST be a separate owner-
privileged step, and the application MUST start safely as the non-owner role by skipping migration
when the database is already migrated. The non-owner role MUST be a real login role that cannot
escalate back to the owner.

#### Scenario: The app role can write but cannot disable the append-only boundary
- **WHEN** a binary connects as the provisioned non-owner application role and attempts to disable the append-only trigger or delete a ledger row, including after resetting its role
- **THEN** the writes the application needs succeed while the disable/delete attempts are refused, and the same operation succeeds only for the database owner
