-- Initial audit ledger schema.
--
-- The ledger is hash-chained, so this migration has no cheap second chance:
-- adding a column later changes what is hashed and breaks chain continuity at
-- the point of change. Every column later phases require exists here, whether
-- or not anything writes it yet.

CREATE TABLE IF NOT EXISTS audit_entries (
    sequence        BIGINT PRIMARY KEY,
    appended_at     TIMESTAMPTZ NOT NULL,

    -- Chain
    prev_hash       BYTEA NOT NULL,
    hash            BYTEA NOT NULL,
    sig             BYTEA NOT NULL,

    -- Decision (nullable: pipeline terminations produce an outcome, no decision)
    decision_id     TEXT,
    event_id        TEXT,
    action          INTEGER,
    confidence      DOUBLE PRECISION,
    reason          TEXT,
    policy_id       TEXT,
    policy_version  TEXT,

    -- Outcome, for terminations that produced no Decision. An Event that
    -- produced no Decision is NOT the same as one that was allowed.
    outcome_kind    TEXT NOT NULL DEFAULT '',
    outcome_stage   TEXT NOT NULL DEFAULT '',

    -- D23 pseudonymous subject, D20 purpose and retention, D27 context version.
    -- Present from migration 001 precisely because retrofitting them would
    -- break the chain.
    subject_id      TEXT NOT NULL DEFAULT '',
    purpose         INTEGER NOT NULL DEFAULT 0,
    retention_class INTEGER NOT NULL DEFAULT 0,
    context_version TEXT NOT NULL DEFAULT ''
);

-- Verification walks in sequence order.
CREATE INDEX IF NOT EXISTS audit_entries_seq_idx ON audit_entries (sequence);
-- T-013's purge job selects by retention class and age.
CREATE INDEX IF NOT EXISTS audit_entries_retention_idx ON audit_entries (retention_class, appended_at);
