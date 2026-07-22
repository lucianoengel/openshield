-- Legal hold registry (HON-2, and the setter SEC-5 depends on).
--
-- Opening an investigation case must HOLD its evidence — a lawful purge (past normal
-- retention age) must NOT erase entries belonging to a subject under an open investigation.
--
-- Design note: the audit's original suggestion was to flip audit_entries.retention_class to
-- the investigation class, but migration 010's append-only trigger makes retention_class an
-- IMMUTABLE integrity column (the hash chain / signatures commit to it) — an UPDATE that
-- changes it is rejected. So the hold is a SEPARATE registry, keyed by the pseudonymous
-- subject (D23), consulted by the purge — it does not mutate the immutable ledger row.
--
-- A hold is placed when a case opens and released when it closes (release is recorded, not
-- deleted, so the hold history is itself auditable).

CREATE TABLE IF NOT EXISTS legal_holds (
    id          BIGSERIAL PRIMARY KEY,
    subject_id  TEXT NOT NULL,          -- the pseudonymous subject whose evidence is held (D23)
    held_by     TEXT NOT NULL,          -- operator:<CN> or system:<...>
    reason      TEXT NOT NULL DEFAULT '',
    held_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ             -- NULL = active hold
);

-- A subject may have at most ONE active hold (a partial unique index over active rows).
CREATE UNIQUE INDEX IF NOT EXISTS legal_holds_active_subject_idx
    ON legal_holds (subject_id) WHERE released_at IS NULL;
