## 1. CloudTrail parser (internal/connectors/cloudtrail)

- [x] 1.1 `Record` struct (event time/source/name, region, source IP, actor arn, error code, account) + a delivery size bound.
- [x] 1.2 `Parse(jsonBytes) ([]Record, int, error)` — decode `{"Records":[…]}`; error on non-JSON/no-Records; count records skipped for missing identity.

## 2. Ingest wiring (internal/controlplane + cmd/openshield-server)

- [x] 2.1 Map a `Record` → `ExternalLog` (vendor=aws, product=cloudtrail, signature_id/name=eventName, severity=errorCode, source_host=sourceIPAddress, message, received_at=eventTime, raw).
- [x] 2.2 `Server.RunCloudTrailIngest(ctx, dir)` — poll dir; per new `*.json`/`*.json.gz`: read (bounded)+gunzip+parse+insert, rename `*.ingested`; a bad file → `*.failed`; `CloudTrailIngested`/`CloudTrailDropped` counters.
- [x] 2.3 Wire into the server leader loop behind `OPENSHIELD_CLOUDTRAIL_DIR`.

## 3. Tests (real path; mutation-verified)

- [x] 3.1 Parser: a real CloudTrail delivery → its fields; a non-JSON / no-Records body → error; a record missing eventName → counted skipped.
- [x] 3.2 Ingest (real PG): drop a file → records persisted + searchable (vendor=aws); the file is renamed `.ingested`; re-running does not double-insert.
- [x] 3.3 Poison file → renamed `.failed` + counted; a valid file dropped after still ingests.
- [x] 3.4 Mutations: `Parse` accepts a body with no `Records` → the reject test FAILs; the ingest does not rename after success → the no-double-insert test FAILs.

## 4. Gate + close

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 4.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 4.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
