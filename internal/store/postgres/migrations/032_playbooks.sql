-- SOAR-4: playbook runs, their steps, and the annotations a playbook produces.
--
-- SOAR-2 (030) made incidents raise and page on a clock; SOAR-3 (031) made four-eyes approval reusable.
-- Neither ACTS. A playbook is the ordered first-response sequence an analyst otherwise repeats by hand —
-- gather what is known, notify, open a case, hold the evidence, tag it — executed by the leader.
--
-- ADR-12 Tier-1: NOTHING here actuates. There is no column for a verb, a target or a command, because a
-- playbook must not be able to express an arbitrary operation (the D14 reason the Action set and the
-- response-intent vocabulary are closed). Actuation is SOAR-7's signed intent seam and SOAR-8's runners,
-- both of which carry four-eyes and blast-radius gating a playbook deliberately does not get.
--
-- All three tables are new; no existing table or index is altered.

CREATE TABLE IF NOT EXISTS playbook_runs (
    id          BIGSERIAL PRIMARY KEY,
    playbook    TEXT NOT NULL,
    incident_id BIGINT NOT NULL,
    -- running | waiting | succeeded | failed. `waiting` is a run parked on a wait-for-approval step:
    -- it holds no goroutine and no connection, so a restart mid-wait is indistinguishable from a tick.
    state       TEXT NOT NULL DEFAULT 'running',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error       TEXT NOT NULL DEFAULT ''
);

-- At most ONE run per (playbook, incident). The engine's start query already excludes incidents that have
-- a run, so this is the backstop rather than the mechanism — the same shape SOAR-1 relies on for "pages
-- exactly once". Without it, two ticks racing (or a leader handover) would open two cases for one incident.
CREATE UNIQUE INDEX IF NOT EXISTS playbook_runs_once_idx ON playbook_runs (playbook, incident_id);

-- The resume scan: which runs are unfinished.
CREATE INDEX IF NOT EXISTS playbook_runs_live_idx ON playbook_runs (state)
    WHERE state IN ('running', 'waiting');

CREATE TABLE IF NOT EXISTS playbook_steps (
    run_id      BIGINT NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    step        TEXT NOT NULL,   -- a name from the CLOSED registry; refused at load, never at execution
    arg         TEXT NOT NULL DEFAULT '',
    -- pending | running | waiting | done | failed
    state       TEXT NOT NULL DEFAULT 'pending',
    approval_id BIGINT,          -- set by wait-for-approval; NULL for every other step
    result      TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, seq)
);

-- The annotations a playbook produces: enrichment summaries, tags and free-text annotations.
--
-- Separate from case_notes on purpose: a note belongs to an INVESTIGATION a human opened, an annotation
-- belongs to the INCIDENT and exists whether or not a case was ever opened. `author` is attributed
-- ('playbook:<name>'), never left to look like a human wrote it.
CREATE TABLE IF NOT EXISTS incident_annotations (
    id          BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    kind        TEXT NOT NULL,   -- enrichment | tag | annotation
    body        TEXT NOT NULL,
    author      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS incident_annotations_incident_idx
    ON incident_annotations (incident_id, created_at);
