## Context

`peer_alerts` (mig 009 + 015 `agent_id` + 016 ack) stores `risk_score` and derives severity at read
time (`scanPeerAlert` calls `Severity(risk)`); there is no dedup/correlation key and no status beyond
the ack boolean. ADR-10 makes severity/status/dedup-key first-class so cross-domain detectors — a HIPS
kill alert has a severity but no `risk_score` — write a uniform lifecycle, and cross-host correlation
can group by a key rather than re-deriving. The project treats a migration as high-stakes (the
migration-count test guards double-apply), so the columns land in one additive migration.

## Goals / Non-Goals

**Goals:**
- Add `severity`, `status`, `dedup_key` to `peer_alerts` in one additive, backfilled migration.
- The current detector (peer-UEBA) writes them; acknowledgement advances `status`; reads return them.
- Keep the columns LIVE (written and read), not forward-declared dead columns.

**Non-Goals:**
- A cross-domain detector actually emitting alerts (future) — this only makes the schema ready.
- A full status state-machine with `closed`/reopen transitions (only `open`→`triaged` is wired now;
  `closed` is a valid value the schema allows).
- Changing `risk_score`, the `Severity` thresholds, or the ack semantics (016).

## Decisions

### D-a · One additive migration, backfilled
`020_alert_lifecycle.sql`: `ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'low'`, `status
TEXT NOT NULL DEFAULT 'open'`, `dedup_key TEXT NOT NULL DEFAULT ''`; backfill `severity` from
`risk_score` (the same thresholds as `Severity`) and `dedup_key = 'peer-ueba:' || subject_id` for
existing rows so history is correct; indexes `(status, severity)` (actionable queue) and `(dedup_key)`
(correlation). Columns inherit the table's grants, so the 017 writer-role grant needs no change.
Migration-count test 19 → 20.

### D-b · Severity is stored, computed at write (ADR-10 supersedes the derived-only rationale)
`recordPeerAlert` stamps `severity = Severity(risk)` at insert. The `Severity`/`severityFloor`
functions stay (peer-UEBA uses `Severity` to compute what to store, and the `min_severity` filter
keeps using the `risk_score` floor — equivalent for peer alerts). `scanPeerAlert` now returns the
STORED `severity` column. The comment in `severity.go` is updated to record the ADR-10 trade-off
(no free re-bucketing on a threshold change; write-time computation keeps peer-alert severity correct).

### D-c · `dedup_key` = detector-namespaced correlation key
`"peer-ueba:" + subject_id` — namespacing by detector so a future `"hips:"`/`"dlp:"` key never
collides, while all peer-UEBA alerts for one subject share a key (the correlation/dedup dimension).
The subject is the entity peer-UEBA alerts on, so this is the natural grouping.

### D-d · `status` lifecycle, advanced by acknowledgement
`status` starts `open`. `AcknowledgeAlert` additionally sets `status = 'triaged'` (in the same
first-ack-wins UPDATE), so the column has two live states and a real transition; `closed` is a valid
future value. This is a richer lifecycle than the ack boolean, which stays as the SEC-11-honest
acknowledged-at/by record.

## Risks / Trade-offs

- **Stored severity cannot re-bucket on a threshold change** → the ADR-10 trade-off for cross-domain
  uniformity; write-time computation keeps new alerts correct and the migration backfills history at
  the current thresholds. Recorded.
- **Additive migration on a table with existing rows** → `ADD COLUMN ... DEFAULT` + a backfill UPDATE
  is safe and idempotent (`IF NOT EXISTS`); the migration-count test proves single-apply.
- **`status` only reaches `triaged`** → `closed`/reopen are future wiring; the schema permits them and
  the column is already live (open→triaged), not a dead forward-declaration.

## Migration Plan

Additive: deploy the migration (backfills existing rows), then the code writes/reads the columns. No
data loss; rollback reverts the code (the columns are harmless if unread). Migration-count test bumped.

## Open Questions

None — ADR-10 fixes the column set and the one-migration approach.
