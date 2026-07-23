## Context

The server leader runs `retain.Loop` → `PurgeOlderThan` (fleet_telemetry) + `PruneNotifyDedupe`, each
returning a row count and driven by an env window (`OPENSHIELD_FLEET_RETENTION`, default 90d). The
counts are logged to stderr and lost. SIEM-10 persists them as compliance evidence.

## Goals / Non-Goals

**Goals:**
- A durable, queryable record of every retention purge (target, count, cutoff, policy, time).
- Recording is best-effort — it never blocks or undoes a purge (a purge cannot be un-done anyway).
- An operator query surface for the compliance report.

**Non-Goals:**
- Recording the gateway-side ledger tombstone purge in THIS increment (same RecordRetentionEvent
  method, called from the gateway, is the follow-on) — this covers the server retention loop.
- A scheduled report EXPORT (PDF/email) — the queryable record is the evidence; export is a follow-on.
- Changing retention behavior — this only observes it.

## Decisions

1. **A dedicated `retention_events` table.** target (fleet_telemetry | notify_dedupe | …), rows_affected,
   cutoff (the boundary), policy (a human string like "OPENSHIELD_FLEET_RETENTION=2160h"), purged_at.
   Indexed by purged_at for the time-windowed report. Inherits the writer-role grant (017).

2. **Best-effort recording.** `RecordRetentionEvent` inserts; a failure is counted
   (`RetentionRecordFailures`) and logged, never returned to the purge loop — the purge already
   happened, and failing the loop would be worse. The report shows what was successfully recorded (a
   gap in the record is itself observable via the counter).

3. **Record only a purge that DID something OR ran.** We record every purge RUN (even a 0-row purge), so
   the report proves the purge is RUNNING on schedule (a compliance question is "is retention actually
   executing?", which a 0-row entry answers), not only that rows were deleted.

4. **`GET /compliance/retention`** on the operator read mux, RoleAnalyst-gated (a read-only report, like
   /logs and /events), with since/until/target/limit filters validated SEC-8-style (a malformed filter
   is a 400, never a silently over-broad compliance answer).
