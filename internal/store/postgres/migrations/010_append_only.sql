-- Append-only ledger at the database level (D63, audit finding #2a).
--
-- Migration 001 left audit_entries mutable: anyone with the connection string
-- could rewrite or truncate the hash chain, so tamper-EVIDENCE was purely a
-- read-time Verify() property. This trigger makes the table append-only in the
-- database: DELETE is forbidden, and UPDATE may not change any INTEGRITY SKELETON
-- column (the columns the hash chain and forward-secure signatures commit to).
--
-- The D36 retention tombstone is still permitted: it nulls only CONTENT columns
-- and sets tombstoned_at, none of which are skeleton columns. Un-tombstoning is
-- forbidden (erasure is one-way).
--
-- HONEST BOUND: a table OWNER can DISABLE this trigger, so this stops the
-- SQL-level / backup-restore / leaked-connection attacker, not a determined one
-- who bypasses it — that is what Verify() and external anchoring (D38) are for.
-- The complete fix is running the ledger under a NON-OWNER restricted role.

CREATE OR REPLACE FUNCTION openshield_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit_entries is append-only: DELETE is forbidden (row %)', OLD.sequence;
    END IF;
    -- UPDATE: the integrity skeleton is immutable.
    IF NEW.sequence        IS DISTINCT FROM OLD.sequence
    OR NEW.appended_at     IS DISTINCT FROM OLD.appended_at
    OR NEW.prev_hash       IS DISTINCT FROM OLD.prev_hash
    OR NEW.hash            IS DISTINCT FROM OLD.hash
    OR NEW.sig             IS DISTINCT FROM OLD.sig
    OR NEW.key_epoch       IS DISTINCT FROM OLD.key_epoch
    OR NEW.retention_class IS DISTINCT FROM OLD.retention_class
    OR NEW.context_version IS DISTINCT FROM OLD.context_version THEN
        RAISE EXCEPTION 'audit_entries is append-only: integrity columns are immutable (row %)', OLD.sequence;
    END IF;
    -- Erasure is one-way: a tombstoned entry cannot be resurrected.
    IF OLD.tombstoned_at IS NOT NULL AND NEW.tombstoned_at IS NULL THEN
        RAISE EXCEPTION 'audit_entries: cannot resurrect a tombstoned entry (row %)', OLD.sequence;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS openshield_audit_append_only_trg ON audit_entries;
CREATE TRIGGER openshield_audit_append_only_trg
    BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW EXECUTE FUNCTION openshield_audit_append_only();
