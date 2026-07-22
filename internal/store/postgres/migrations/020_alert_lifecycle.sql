-- Unified alert lifecycle schema (SIEM-6b / ADR-10).
--
-- peer_alerts already carried agent_id (015) and the ack columns (016), but severity was DERIVED at
-- read time from risk_score, there was no correlation/dedup key, and the only lifecycle state was the
-- ack boolean. That limits cross-host correlation and any future cross-domain detector: a HIPS kill
-- alert has a severity but no peer-UEBA risk_score. ADR-10: make severity / status / dedup_key
-- first-class in ONE migration now, so every detector writes a uniform lifecycle from day one, before
-- more SIEM detection ships and a later migration gets costly.
--
-- severity is stored (computed at write from risk) rather than derived — the ADR-10 trade-off is that
-- a later threshold change no longer re-buckets history, in exchange for a column a non-risk detector
-- can also write. status is the lifecycle beyond the ack boolean (open -> triaged -> closed). dedup_key
-- is a detector-namespaced correlation key ("peer-ueba:<subject>") so keys from different detectors
-- never collide while same-subject peer alerts group together.
--
-- Columns inherit peer_alerts' grants, so the 017 writer-role grant needs no change. Existing rows are
-- backfilled so history is correct.
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'low';
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS dedup_key TEXT NOT NULL DEFAULT '';

-- Backfill existing rows: severity from risk_score (same inclusive lower bounds as Severity()), and a
-- namespaced dedup_key from the subject.
UPDATE peer_alerts
   SET severity = CASE
       WHEN risk_score >= 0.90 THEN 'critical'
       WHEN risk_score >= 0.75 THEN 'high'
       WHEN risk_score >= 0.50 THEN 'medium'
       ELSE 'low'
   END
 WHERE severity = 'low';
UPDATE peer_alerts SET dedup_key = 'peer-ueba:' || subject_id WHERE dedup_key = '';

-- The actionable queue orders by status + severity; correlation groups by dedup_key.
CREATE INDEX IF NOT EXISTS peer_alerts_status_severity_idx ON peer_alerts (status, severity);
CREATE INDEX IF NOT EXISTS peer_alerts_dedup_idx ON peer_alerts (dedup_key);
