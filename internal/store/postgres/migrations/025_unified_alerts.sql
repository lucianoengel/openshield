-- Unified, entity-keyed alert stream (XDR-2).
--
-- XDR-1 (migration 021) gave a durable device⋈user entity graph; SIEM-6b/ADR-10 (020) made peer_alerts
-- carry severity/status/dedup_key and stated "a future cross-domain detector writes the same shape".
-- This is that table: domain-agnostic and keyed by entity_id (the XDR graph entity), so EVERY domain's
-- detections land in ONE normalized stream a single correlation engine (XDR-4) reads. peer_alerts stays
-- (it carries UEBA-specific risk_score/context_version); a unified_alerts row is the normalized
-- projection the correlation layer reads.
--
-- entity_id is the correlation key (a device/user resolved through the graph, not a bare subject
-- string), so alerts from different domains for the same asset GROUP by an entity join. domain labels
-- the source (ueba/dlp/hips/nips/zt/…). dedup_key is a detector-namespaced idempotency key (a UNIQUE
-- constraint dedupes a re-detection to one row, so correlation input is not multiplied). detected_at is
-- when the detector fired. The table inherits the non-owner writer-role grant via 017 default privileges.
CREATE TABLE IF NOT EXISTS unified_alerts (
    id          BIGSERIAL PRIMARY KEY,
    entity_id   BIGINT NOT NULL,
    domain      TEXT NOT NULL,
    subject_id  TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'low',
    title       TEXT NOT NULL DEFAULT '',
    dedup_key   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT unified_alerts_dedup_key_uniq UNIQUE (dedup_key)
);

-- The per-entity cross-domain read (AlertsForEntity), newest first.
CREATE INDEX IF NOT EXISTS unified_alerts_entity_idx ON unified_alerts (entity_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS unified_alerts_domain_idx ON unified_alerts (domain, detected_at DESC);
