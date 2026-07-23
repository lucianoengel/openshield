## 1. Schema + store
- [x] 1.1 Migration `026_retention_events.sql` (target, rows_affected, cutoff, policy, purged_at) + purged_at index; count test 25→26.
- [x] 1.2 `RetentionEvent` type; `RecordRetentionEvent` (best-effort, counts `RetentionRecordFailures`); `RetentionReport` + filter.

## 2. Wire + endpoint
- [x] 2.1 Server retention loop records the fleet + notify-dedupe purges (best-effort).
- [x] 2.2 `GET /compliance/retention` on the operator mux, RoleAnalyst-gated, `parseRetentionFilter` (400 on malformed).

## 3. Tests (real PG; mutation-verified)
- [x] 3.1 Record events → `RetentionReport` returns them (windowed, newest-first); a 0-row purge is recorded.
- [x] 3.2 `/compliance/retention` returns events; a malformed filter → 400.
- [x] 3.3 Mutations: RecordRetentionEvent no-ops → the report test FAILs; parse accepts a bad `since` → the 400 test FAILs.

## 4. Gate + close
- [x] 4.1 `make all` green; cross-compile; restore binaries.
- [x] 4.2 `decisions.md`; sync spec; doccheck.
- [x] 4.3 Archive; commit; push; roadmap.
