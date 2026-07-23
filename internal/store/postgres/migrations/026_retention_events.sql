-- Retention compliance reporting (SIEM-10).
--
-- OpenShield enforces retention (the leader purges fleet-aggregate telemetry + prunes the notify-dedupe
-- ledger past their windows, D81/D20) but kept NO record of it — a compliance auditor ("prove data
-- older than 90 days is deleted; when, how much, under which policy") had nothing to point at. This
-- table records each purge RUN as a first-class compliance event.
--
-- target names what was purged (fleet_telemetry | notify_dedupe | …); rows_affected is how many rows
-- the run removed (0 is recorded too — it proves the purge is EXECUTING on schedule); cutoff is the
-- retention boundary applied; policy is the human-readable driver (e.g. the configured window);
-- purged_at is when it ran. Indexed by purged_at for the time-windowed report. Inherits external_logs'
-- writer-role grant via 017 default privileges.
CREATE TABLE IF NOT EXISTS retention_events (
    id            BIGSERIAL PRIMARY KEY,
    purged_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    target        TEXT NOT NULL,
    rows_affected BIGINT NOT NULL DEFAULT 0,
    cutoff        TIMESTAMPTZ,
    policy        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS retention_events_purged_idx ON retention_events (purged_at DESC);
