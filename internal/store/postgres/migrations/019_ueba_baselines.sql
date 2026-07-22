-- Persisted peer-UEBA baselines (SIEM-5, = SEC-10).
--
-- The analyzer's per-subject baseline (decayed activity count as of a last-seen time) is
-- in-memory and lost on restart, so for ~one decay half-life after every restart or deploy the
-- analyzer has NO baseline and fires no peer anomalies — a silent detection gap. The control
-- plane snapshots the baseline here periodically and on shutdown, and reloads it when peer-UEBA
-- is enabled, so a restart resumes the warm baseline. Restoration is EXACT: decay is computed
-- forward from last_seen at query time, so storing {count, last_seen} verbatim reproduces the
-- risk (no decay is applied at store or load time).
--
-- One row per pseudonymous subject (D23); UPSERT keyed on subject makes re-persisting a warm
-- fleet idempotent. The 017 ALTER DEFAULT PRIVILEGES already grants this owner-created table to
-- the non-owner openshield_writer role, so no explicit GRANT is needed here.

CREATE TABLE IF NOT EXISTS ueba_baselines (
    subject    TEXT PRIMARY KEY,
    count      DOUBLE PRECISION NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
