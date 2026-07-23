-- Durable notification idempotency (SIEM-12 / R34-13).
--
-- SIEM-12 (migration-free, D172) deduped delivered alerts by a deterministic id in an IN-PROCESS set,
-- so a restart/failover forgot it and the same alert re-detected in the same window paged AGAIN. This
-- table makes the "page exactly once" guarantee durable: emit records the id here (INSERT ON CONFLICT
-- DO NOTHING), and a zero-row result means the id was already emitted — this process OR a prior one —
-- so the re-detection is suppressed across restarts.
--
-- Distinct from peer_alerts.dedup_key (a CORRELATION key on the recorded alert): this is a
-- delivery-idempotency ledger keyed by the notification id — overdue-agent pages have no peer_alerts
-- row, and a suppressed re-detection must not write an alert row. emitted_at exists only for pruning
-- (an id need only outlive its dedup window). The table auto-grants to the non-owner writer role via
-- migration 017's default privileges.
CREATE TABLE IF NOT EXISTS notify_dedupe (
    id          TEXT PRIMARY KEY,
    emitted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pruning deletes by age, so index emitted_at.
CREATE INDEX IF NOT EXISTS notify_dedupe_emitted_idx ON notify_dedupe (emitted_at);
