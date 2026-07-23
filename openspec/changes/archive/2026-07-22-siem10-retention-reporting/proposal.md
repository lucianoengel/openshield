## Why

OpenShield enforces retention — the leader purges the fleet-aggregate telemetry and prunes the
notify-dedupe ledger past their windows (D81/D20), tombstoning bounded-class ledger entries — but keeps
NO record of what it did. A compliance auditor ("prove personal-adjacent telemetry older than 90 days
is deleted; show me when, how much, under which policy") has nothing to point at. SIEM-10: record each
retention purge as a first-class, queryable compliance event.

## What Changes

- **A `retention_events` table**: each purge records its target, the row count removed, the cutoff
  timestamp (the retention boundary), the policy that drove it (the configured window), and when it ran.
- **`Server.RecordRetentionEvent` + `RetentionReport`**: a best-effort recorder the purge loop calls,
  and a time-windowed query — the compliance report.
- **The server retention loop records what it purges** (fleet-aggregate rows, notify-dedupe ids),
  best-effort (a recording failure is logged, never undoes or blocks the purge).
- **`GET /compliance/retention`**: an operator query over the retention events (RoleAnalyst-gated, SEC-8
  filter validation), so the compliance record is accessible via the API.

## Capabilities

### New Capabilities
- `retention-reporting`: a queryable record of what retention purged, when, how much, and under which
  policy — the compliance evidence for the retention guarantee.

### Modified Capabilities
<!-- none: adds recording + a query around the existing purge loop. -->

## Impact

- `internal/store/postgres`: migration `026_retention_events.sql` + count test 25 → 26.
- `internal/controlplane`: `RetentionEvent` type; `RecordRetentionEvent` (best-effort);
  `RetentionReport`/`RetentionReportFilter`; `parseRetentionFilter`; a `/compliance/retention` handler
  on the operator mux; `RetentionRecordFailures` counter.
- `cmd/openshield-server`: the retention loop records each purge.
- No proto/core change, no new dependency.
