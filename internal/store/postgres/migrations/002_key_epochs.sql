-- Persist the public-key chain.
--
-- Until this migration the epoch public keys lived only in the in-memory
-- Signer, so verification worked only inside the process that did the writing.
-- A second process (the CLI) or a restart with a fresh signer had no chain to
-- verify against — the forward-security property D30 claims was true of the
-- algorithm and false of the deployed system.
--
-- Public material only. The private key is never written; there is no column
-- for it, and a test asserts that.

CREATE TABLE IF NOT EXISTS key_epochs (
    idx         BIGINT PRIMARY KEY,   -- epoch index; 0 is the anchor
    public_key  BYTEA NOT NULL,       -- signs entries in this epoch
    sig_by_prev BYTEA                 -- this public key signed by epoch idx-1; NULL for the anchor
);

-- An entry may only reference an epoch whose public key is stored. Without this
-- an evolution that failed to persist its epoch would produce an entry nobody
-- can verify — and it would fail at AUDIT time, long after the fact. The foreign
-- key moves that failure to write time, where it is actionable.
ALTER TABLE audit_entries
    ADD CONSTRAINT audit_entries_key_epoch_fk
    FOREIGN KEY (key_epoch) REFERENCES key_epochs (idx);
