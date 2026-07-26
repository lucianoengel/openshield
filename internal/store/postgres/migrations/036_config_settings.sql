-- PLAT-5b: database-authoritative dynamic configuration, with revisions.
--
-- The split this implements: BOOTSTRAP settings (what a process needs to start and reach this database)
-- stay in env/file; everything else is DYNAMIC and lives here, so changing one changes it for the whole
-- deployment without touching a host. That is the static/dynamic split serious platforms make explicit,
-- rather than the layered-config-file model where the console and the host can disagree silently.
--
-- SECRETS ARE NEVER STORED HERE. The write path refuses a secret field outright — not encrypted, not
-- referenced-then-stored. A dump of this database must not be a dump of the deployment's credentials.

-- What is currently in effect.
CREATE TABLE IF NOT EXISTS config_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    revision   BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WHO changed it and when. A change is a revision, not a write.
CREATE TABLE IF NOT EXISTS config_revisions (
    id     BIGSERIAL PRIMARY KEY,
    author TEXT NOT NULL,
    note   TEXT NOT NULL DEFAULT '',
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WHAT it changed from. Rollback restores these values as a NEW revision rather than deleting rows: an
-- audit trail you can rewind by erasing is not one.
CREATE TABLE IF NOT EXISTS config_changes (
    revision_id BIGINT NOT NULL REFERENCES config_revisions(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    old_value   TEXT NOT NULL DEFAULT '',
    new_value   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (revision_id, key)
);

-- The live-apply watcher polls max(id); the per-revision diff read is by revision.
CREATE INDEX IF NOT EXISTS config_changes_revision_idx ON config_changes (revision_id);
