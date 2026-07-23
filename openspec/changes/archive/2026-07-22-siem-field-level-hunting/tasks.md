## 1. Schema

- [x] 1.1 Migration `024_external_log_fields.sql` — `ALTER TABLE external_logs ADD COLUMN fields JSONB NOT NULL DEFAULT '{}'` + a GIN index.
- [x] 1.2 Bump the migration-count test 23 → 24.

## 2. Store

- [x] 2.1 `ExternalLog.Fields map[string]string`; `InsertExternalLog` marshals it to JSONB (`'{}'` when empty).
- [x] 2.2 `ExternalLogFilter.FieldKey`/`FieldValue`; `SearchExternalLogs` adds `fields->>$key = $value` when set; scan `fields` back.
- [x] 2.3 `parseExternalLogFilter` parses `?field=key:value` (400 on empty key / no colon).

## 3. Mappers populate Fields

- [x] 3.1 CEF mapper → `msg.Extensions`; WEF mapper → `rec.Data`; CloudTrail mapper → a small map of its parsed fields.

## 4. Tests (real PG; mutation-verified)

- [x] 4.1 Insert logs with fields; search by a field key=value returns only the matching rows; a non-matching value returns none.
- [x] 4.2 Cross-source: a CEF and a WEF log sharing a field value both returned by one field search.
- [x] 4.3 `/logs?field=key:value` end-to-end returns the matching log; `?field=nocolon` and `?field=:v` → 400.
- [x] 4.4 Mutations: `SearchExternalLogs` ignores the field filter → the "only matching" test FAILs; `parseExternalLogFilter` accepts a colon-less field → the 400 test FAILs.

## 5. Gate + close

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 5.2 `decisions.md` entry; sync delta specs into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 5.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
