## Why

The SIEM ingest lane (CEF D205, CloudTrail D208, WEF D211) parses rich per-event fields — CEF
extension key=values, CloudTrail's actor/region/error, WEF's EventData Name/Value pairs — but only a
FIXED subset is columnised (vendor/product/signature/name/severity/host/message). The rest survives in
`external_logs.raw` as opaque text, so an analyst can filter by vendor or host but CANNOT hunt on
"every event where `TargetUserName=svc-backup`" or "`sourceIPAddress=203.0.113.7` across CloudTrail AND
WEF". The roadmap flags this: external-log fields are not queryable. This makes the parsed fields
first-class and huntable.

## What Changes

- **A `fields JSONB` column** on `external_logs` (migration): every parsed per-event field
  (CEF extensions, WEF EventData, CloudTrail's parsed fields) is stored as a JSON object, with a GIN
  index for containment queries.
- **The ingest mappers populate `Fields`**: the CEF, WEF, and CloudTrail mappers hand their parsed
  key/value maps into `ExternalLog.Fields`, so the data that was only in `raw` is now structured.
- **Field-level search**: `SearchExternalLogs` gains a `Field` filter (`key`,`value`) → `fields->>key =
  value`, and `GET /logs` accepts `?field=key:value` — a hunt across ALL sources by an arbitrary parsed
  field. Malformed field syntax is a 400 (SEC-8), consistent with the other filters.

No new store, no proto/core change — a JSONB column + the mappers filling it + one filter.

## Capabilities

### New Capabilities
<!-- none: this deepens the existing external-log capabilities. -->

### Modified Capabilities
- `cef-syslog-ingest`: the CEF extension fields are now stored structured and searchable.
- `cloudtrail-ingest`: CloudTrail's parsed fields are now stored structured and searchable.
- `wef-ingest`: WEF EventData fields are now stored structured and searchable.

## Impact

- `internal/store/postgres`: migration `024_external_log_fields.sql` (`fields JSONB` + a GIN index).
- `internal/controlplane`: `ExternalLog.Fields map[string]string`; `InsertExternalLog` marshals it to
  JSONB; `SearchExternalLogs`/`ExternalLogFilter` gain a `Field` filter; `parseExternalLogFilter`
  parses `?field=key:value`; the CEF/WEF/CloudTrail mappers populate `Fields`.
- `internal/store/postgres/postgres_test.go`: migration count 23 → 24.
- No proto/core change, no new dependency.
