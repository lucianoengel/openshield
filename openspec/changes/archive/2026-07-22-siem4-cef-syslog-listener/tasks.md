## 1. CEF-from-syslog extraction (internal/connectors/cef)

- [x] 1.1 `FromSyslog(syslogMsg string) (Message, bool)` — locate `CEF:` in the free text, parse from there; `(_, false)` for no-CEF or malformed-CEF.

## 2. External-log store (internal/store/postgres)

- [x] 2.1 Migration `022_external_logs.sql` — `external_logs(id, received_at, source_host, vendor, product, signature_id, name, severity, message, raw)` + helpful indexes.
- [x] 2.2 `ExternalLog` type + `InsertExternalLog(ctx, ExternalLog)`.
- [x] 2.3 `ExternalLogFilter` + `SearchExternalLogs(ctx, filter)` — time window + vendor/product/host/severity + capped limit, newest first.

## 3. Listener wiring (internal/controlplane + cmd/openshield-server)

- [x] 3.1 `Server.RunCEFSyslog(ctx, addr)` — run `syslog.Listen` with a sink that `FromSyslog`s + `InsertExternalLog`s; `CEFIngested`/`CEFDropped` counters.
- [x] 3.2 `Server.SearchExternalLogs` pass-through to the store.
- [x] 3.3 Wire into the server leader loop behind `OPENSHIELD_CEF_SYSLOG_LISTEN`.

## 4. Tests (real path; mutation-verified)

- [x] 4.1 `FromSyslog`: a real CEF-over-syslog line extracts its fields; a non-CEF line reports no-CEF; a malformed CEF payload reports no-CEF.
- [x] 4.2 Store round-trip (real PG): insert → search by vendor/window returns the record with fields intact; limit is capped.
- [x] 4.3 End-to-end (real UDP socket + real PG): send a CEF-over-syslog datagram to `RunCEFSyslog` → it is persisted and found by search; a non-CEF datagram increments the drop/skip counter and the listener keeps serving.
- [x] 4.4 Mutations: `FromSyslog` returns true for a non-CEF line → the skip test FAILs; the listener sink ignores the persist (never inserts) → the end-to-end search FAILs.

## 5. Gate + close

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`; restore tracked binaries.
- [x] 5.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 5.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap status.
