## 1. WEF parser (internal/connectors/wef)

- [x] 1.1 `Record` struct (event id, provider, level, time, computer, channel, EventData map) + a delivery size bound.
- [x] 1.2 `Parse(xmlBytes) ([]Record, int, error)` — streaming scan for `<Event>` (single or `<Events>` batch); error on malformed XML; count records skipped for missing EventID.

## 2. Shared ingest helper + WEF wiring (internal/controlplane + cmd/openshield-server)

- [x] 2.1 Extract `scanIngestDir(ctx, dir, isTarget, ingestOne)` from the CloudTrail poller; refactor `scanCloudTrailDir` onto it (CloudTrail tests gate the refactor).
- [x] 2.2 Map a WEF `Record` → `ExternalLog` (vendor=microsoft, product=windows, signature_id=EventID, name=provider/EventID, severity=Level, source_host=Computer, received_at=TimeCreated, message, raw).
- [x] 2.3 `Server.RunWEFIngest(ctx, dir)` + `ingestWEFFile` (read+gunzip+parse+insert) + `isWEFFile` + `WEFIngested`/`WEFDropped` counters.
- [x] 2.4 Wire into the server leader loop behind `OPENSHIELD_WEF_DIR`.

## 3. Tests (real path; mutation-verified)

- [x] 3.1 Parser: a single logon event → its fields; an `<Events>` batch → N records; malformed XML → error; a record with no EventID → counted skipped.
- [x] 3.2 Ingest (real PG): drop a WEF file → events persisted + searchable (vendor=microsoft); file renamed `.ingested`; re-run no double-insert.
- [x] 3.3 Poison file → renamed `.failed` + counted; a valid file after still ingests.
- [x] 3.4 Mutations: `Parse` treats malformed XML as empty (no error) → the reject test FAILs; the ingest does not rename after success → the no-double-insert test FAILs.
- [x] 3.5 CloudTrail's existing ingest tests still pass (the shared-helper refactor is behavior-preserving).

## 4. Gate + close

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 4.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 4.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
