## Why

`peer_alerts` carries `agent_id` (mig 015) and ack columns (016), but **severity, a correlation/dedup
key, and a status lifecycle beyond ack are not first-class columns** — severity is derived at read
time from `risk_score`, there is no dedup/correlation key, and the only lifecycle state is the boolean
ack. Cross-host correlation and any future cross-domain detector (HIPS/DLP alerts have a severity but
no peer-UEBA `risk_score`) are limited by this schema. ADR-10: add them in **one migration now**, so
every detector writes the lifecycle fields from day one — before more SIEM detection ships and makes a
later migration costly.

## What Changes

- One migration adds `severity`, `status` (`open`→`triaged`→`closed`), and `dedup_key` to
  `peer_alerts`, backfilling `severity`/`dedup_key` for existing rows, with indexes for the actionable
  queue and correlation. **BREAKING** (schema): migration count 19 → 20.
- The peer-UEBA detector writes them: `recordPeerAlert` stamps `severity = Severity(risk)`, `status =
  'open'`, and `dedup_key = "peer-ueba:" + subject` on insert.
- Acknowledgement transitions `status` `open` → `triaged` (the lifecycle beyond the ack boolean).
- Reads expose the stored `severity`/`status`/`dedup_key` (severity now comes from the column, not a
  read-time derivation).
- **Trade-off recorded:** severity was deliberately derived (re-buckets on a threshold change without a
  migration). ADR-10 stores it for cross-domain uniformity; it is computed at WRITE from the current
  thresholds, so peer-alert severity is correct, but a later threshold change no longer re-buckets
  history. Accepted per ADR-10.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `control-plane`: a peer alert carries first-class `severity`, `status` (open→triaged→closed), and a
  `dedup_key` correlation key; acknowledgement advances the status; reads return the stored fields.

## Impact

- **Code:** `internal/store/postgres/migrations/020_alert_lifecycle.sql` (+ migration-count test 19→20),
  `internal/controlplane/signed.go` (`recordPeerAlert` writes the fields),
  `internal/controlplane/alert_ack.go` (ack → `status='triaged'`),
  `internal/controlplane/operator_read.go` (columns + struct + scan), `severity.go` (comment update).
- **No proto/core change.** The migration is additive; existing rows are backfilled.
