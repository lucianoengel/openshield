-- Materialized incidents (SIEM-11b).
--
-- Correlation (D65/D131) computed incidents ON READ — a query over peer_alerts run per GET. That
-- gave incidents no identity and no state, so the SIEM-6 acknowledgement could only attach to
-- individual alerts, and a case (D107) could not target an incident as a UNIT. This table persists
-- a correlated incident with a stable id and a lifecycle state, so an operator can acknowledge or
-- open a case against the incident itself.
--
-- One OPEN incident per subject at a time: a re-correlated burst UPDATES the subject's open
-- incident (extends its span, refreshes its counts) rather than creating a duplicate. Acknowledging
-- or closing it lets a later burst open a NEW incident — the partial unique index enforces this.
CREATE TABLE IF NOT EXISTS incidents (
    id              BIGSERIAL PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged
    alert_count     INTEGER NOT NULL,
    max_risk        DOUBLE PRECISION NOT NULL,
    host_count      INTEGER NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one OPEN incident per subject — the upsert conflict target.
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_subject_idx ON incidents (subject_id) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents (state, last_seen);
