-- Retention tombstone (T-013).
--
-- Enforced retention (GDPR Art. 5/17) requires erasing expired personal data,
-- but the ledger is hash-chained: DELETING a row breaks every row after it.
-- Tombstoning resolves this — a purge erases the content columns but keeps the
-- skeleton (sequence, prev_hash, hash, sig, key_epoch), and verification treats
-- a tombstoned row as an authenticated link without recomputing its hash from
-- content that is deliberately gone.
--
-- tombstoned_at NULL means live; non-NULL is the erasure time.

ALTER TABLE audit_entries ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ;

-- The purge job selects expired, live entries by class and age.
CREATE INDEX IF NOT EXISTS audit_entries_tombstone_idx
    ON audit_entries (tombstoned_at, retention_class, appended_at);
