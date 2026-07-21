# audit-ledger delta

## ADDED Requirements

### Requirement: The ledger is append-only at the database level
The audit ledger MUST reject, at the database, any DELETE of an entry and any UPDATE that changes an
integrity column (sequence, appended_at, prev_hash, hash, sig, key_epoch, retention_class,
context_version), so a leaked connection string cannot rewrite or truncate history through ordinary
SQL — tamper-resistance is not left solely to a read-time verification.

The D36 retention tombstone MUST still succeed, because it mutates only content columns and sets
tombstoned_at. Resurrecting a tombstoned entry (clearing tombstoned_at) MUST be rejected. This is
defence in depth: a table owner who disables the control can still tamper, and that is caught by
Verify() and external anchoring (D38), which remain the guarantee against a determined adversary.

#### Scenario: A leaked connection cannot delete or rewrite an entry
- **WHEN** the app role attempts to DELETE an audit entry or UPDATE its hash
- **THEN** the database rejects both
- **AND** a test asserts the delete and the hash update both error

#### Scenario: Retention tombstoning still works
- **WHEN** retention tombstones an expired entry (nulls content columns, sets tombstoned_at)
- **THEN** the update succeeds and the entry's skeleton is unchanged
- **AND** a test asserts the tombstone succeeds and the chain remains verifiable

#### Scenario: Verify still catches a tamper that bypasses the control
- **WHEN** an adversary bypasses the database control (disables the trigger, e.g. as a table owner)
  and modifies or deletes an entry
- **THEN** Verify() still detects and locates the tampering
- **AND** a test performs the bypass, tampers, and asserts Verify() reports it
