-- SOAR-10: incidents raised RETROSPECTIVELY are marked as such.
--
-- Correlation runs over a look-back window on a clock. Alerts that fall outside it are never correlated,
-- and the ones that matter most are exactly the ones that fell outside because correlation was NOT
-- RUNNING: a leader outage, an interval left at zero, a deployment gap. Those alerts sit in the store
-- forever, individually visible and never joined, and the incident that should have paged somebody simply
-- does not exist. Nothing reports its absence, because nothing knows it was supposed to be there.
--
-- Backfill is running the same rules over a historical range. The column exists because a backfilled
-- incident is NOT the same thing as one raised live, and treating it as one corrupts the two places its
-- timestamps are read:
--
--   * RESPONSE METRICS. `created_at` for a backfilled incident is when the backfill ran, not when
--     detection happened. Its detection latency is the age of the alert, its time-to-acknowledge starts
--     from a moment no analyst could have acted on, and both would be averaged in with real ones.
--   * NOTIFICATION. A month of backfill would page the SOC for hundreds of incidents that are long over.
--
-- Both are handled by knowing which incidents these are, so the flag is not bookkeeping — it is what
-- makes the feature safe to use at all.
--
-- Additive: existing rows are false, which is exactly what they are (raised live).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS backfilled BOOLEAN NOT NULL DEFAULT false;

-- The metrics queries filter on it, and a backfill of a long range writes many rows.
CREATE INDEX IF NOT EXISTS incidents_backfilled_idx ON incidents (backfilled) WHERE backfilled;
