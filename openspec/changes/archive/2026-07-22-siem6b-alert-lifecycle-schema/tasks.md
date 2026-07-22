## 1. Migration

- [x] 1.1 `020_alert_lifecycle.sql`: `ADD COLUMN IF NOT EXISTS` `severity TEXT NOT NULL DEFAULT 'low'`,
      `status TEXT NOT NULL DEFAULT 'open'`, `dedup_key TEXT NOT NULL DEFAULT ''`; backfill `severity`
      from `risk_score` (same thresholds as `Severity`) and `dedup_key = 'peer-ueba:' || subject_id`;
      indexes `(status, severity)` and `(dedup_key)`.
- [x] 1.2 Bump the migration-count test 19 → 20; add `020` to any migration-file listing if present.

## 2. Detector writes the fields; ack advances status

- [x] 2.1 `recordPeerAlert`: INSERT `severity = Severity(risk)`, `status = 'open'`,
      `dedup_key = "peer-ueba:" + subject`.
- [x] 2.2 `AcknowledgeAlert`: in the same first-ack-wins UPDATE, also set `status = 'triaged'`.

## 3. Reads expose the stored fields

- [x] 3.1 `peerAlertColumns` += `severity, status, dedup_key`; `PeerAlert` struct += `Status`,
      `DedupKey` (JSON), and `Severity` now scanned from the column (not `Severity(risk)`); update
      `scanPeerAlert` in lockstep.
- [x] 3.2 Update the `severity.go` comment to record the ADR-10 trade-off (severity now stored,
      computed at write; no free re-bucketing on a threshold change).

## 4. Verify + mutation guards

- [x] 4.1 Real-PG test: a recorded peer alert has stored `severity` matching `Severity(risk)`, `status
      = 'open'`, and `dedup_key = "peer-ueba:"+subject`; after `AcknowledgeAlert`, its `status` is
      `triaged` and the ack fields are set; the read surface returns the stored fields.
- [x] 4.2 Migration test: fresh DB has 20 migrations; the new columns exist with the right defaults; a
      pre-existing row (inserted without the columns via a raw INSERT of the base columns) reads back a
      backfilled severity/dedup_key.
- [x] 4.3 Mutation guards (apply, FAIL, revert): (A) don't write `severity`/`dedup_key` in
      `recordPeerAlert` (leave defaults) → the stored-severity/dedup assertion FAILs; (B) drop the
      `status='triaged'` in ack → the status-advances assertion FAILs. Record it. (Confirmed 2026-07-22: (A) revert recordPeerAlert to the base insert → stored severity 'low' not 'high' → FAIL; (B) drop status='triaged' in ack → status stays 'open' → FAIL; both reverted.)

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 5.2 decisions.md entry (next D-number).
- [x] 5.3 Roadmap + memory updated.
