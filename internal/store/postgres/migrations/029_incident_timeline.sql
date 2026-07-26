-- XDR-5: the cross-domain incident timeline.
--
-- XDR-4 (028) raises an entity-keyed incident carrying counts and discards WHICH alerts it aggregated,
-- so an operator sees "4 alerts across 3 domains" and cannot see what happened. Three additions close
-- that: the contributing-alert join, an evidence reference on each alert, and the incident's domain list.
--
-- All additive. No backfill: alerts and incidents recorded before this migration carry no reference and
-- no join rows, and inventing an evidence link that was never captured would be fabricating provenance.

-- Which alerts an incident is made of. The composite primary key is what makes the materializer's
-- ON CONFLICT DO NOTHING converge: a re-correlation of an open incident sees the same alerts again, and
-- the evidence set must be the UNION, not a set that multiplies on every scheduled tick.
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id BIGINT NOT NULL,
    alert_id    BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, alert_id)
);

-- The per-incident timeline read.
CREATE INDEX IF NOT EXISTS incident_alerts_incident_idx ON incident_alerts (incident_id);

-- The incident's distinct domains, so an incident list is legible without a join per row. Written from
-- the same aggregate that produced domain_count, so the two cannot disagree.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS domains TEXT[];

-- EVIDENCE REFERENCES on a unified alert: what produced it.
--
-- The decision id is currently recoverable only by parsing it back out of dedup_key ('decision:<id>'),
-- and dedup_key is an idempotency key whose format is a projection detail — it already has a fallback
-- form. Building the alert→evidence path on it would let a cosmetic change to a key silently break the
-- one link in the timeline that must not rot.
--
-- Both are NULLABLE, and NULL is MEANINGFUL rather than missing: a server-side peer-UEBA alert is a
-- derivation with no originating endpoint event or decision, which the timeline reports as its own state
-- ('derived') rather than as an empty field.
ALTER TABLE unified_alerts ADD COLUMN IF NOT EXISTS event_id    TEXT;
ALTER TABLE unified_alerts ADD COLUMN IF NOT EXISTS decision_id TEXT;

-- Evidence resolution looks up audit_entries by decision id (never fleet_telemetry — the aggregate is
-- not the evidentiary ledger, D30), so index both sides of that lookup.
CREATE INDEX IF NOT EXISTS unified_alerts_decision_idx ON unified_alerts (decision_id)
    WHERE decision_id IS NOT NULL;

-- An INDEX on the ledger is safe where a COLUMN would not be: migration 001 warns that adding a column
-- changes what is hashed and breaks chain continuity, but an index is not part of an entry's hashed
-- content. Without it, resolving a timeline's evidence sequentially scans the whole append-only ledger.
CREATE INDEX IF NOT EXISTS audit_entries_decision_idx ON audit_entries (decision_id)
    WHERE decision_id IS NOT NULL;
