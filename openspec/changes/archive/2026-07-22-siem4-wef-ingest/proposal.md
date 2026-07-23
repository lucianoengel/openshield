## Why

SIEM-4 shipped CEF-over-syslog (D202/D205) and AWS CloudTrail cloud-JSON (D208), and its scope named
the third format: **WEF (Windows Event Forwarding XML)**. Windows endpoints and domain controllers emit
security events (logon 4624/4625, privilege use, process creation 4688, account changes) as the
standard Windows Event XML; a Windows Event Collector forwards them. Today those events land nowhere,
so the SIEM is blind to the largest endpoint estate in most organizations. This adds the WEF XML parser
and ingest, completing the CEF/CloudTrail/WEF trilogy over the SAME `external_logs` store and `/logs`
query surface.

## What Changes

- **A WEF XML parser** (`internal/connectors/wef`): `Parse(xml) → []Record` decodes the standard Windows
  Event schema (`<Event><System>…</System><EventData>…</EventData></Event>`, single or wrapped in
  `<Events>…</Events>`) into the security-relevant fields — EventID, Provider, Level, TimeCreated,
  Computer, Channel, and the `EventData` Name/Value pairs. A faithful decoder over the FIXED schema (no
  heuristic guessing); malformed XML is an error, a record missing an EventID is counted-skipped.
- **A shared directory-ingest helper** (`Server.scanIngestDir`): the scan + `.ingested`/`.failed` rename
  idempotency logic is extracted from the CloudTrail poller so both formats share it (CloudTrail
  refactored to use it — its tests verify no regression).
- **`Server.RunWEFIngest(ctx, dir)`**: ingests WEF `*.xml`/`*.xml.gz` files dropped into a directory
  (the WEC-export pattern), maps each event onto the shared `ExternalLog` (vendor=microsoft,
  product=windows), and is wired into the server leader loop behind `OPENSHIELD_WEF_DIR`. Searchable by
  the SAME `/logs` endpoint (vendor=microsoft) as CEF and CloudTrail.

No new store, no new proto, no new dependency — a new parser + the shared ingest helper over the
existing external-log store and query surface.

## Capabilities

### New Capabilities
- `wef-ingest`: parsing Windows Event Forwarding XML and persisting each event as a searchable
  external-log record, so Windows endpoint/DC security events are queryable beside CEF, CloudTrail, and
  agent telemetry.

### Modified Capabilities
<!-- none: reuses external_logs + /logs; the cloudtrail-ingest capability's behavior is unchanged (only
     its poller now shares a helper). -->

## Impact

- `internal/connectors/wef`: `Parse` + `Record` + `EventData` + a delivery size bound.
- `internal/controlplane`: `scanIngestDir` (shared, extracted from CloudTrail) + `RunWEFIngest` +
  `ingestWEFFile` + `wefToExternalLog` + `WEFIngested`/`WEFDropped` counters; `RunCloudTrailIngest`
  refactored onto the shared helper.
- `cmd/openshield-server`: run the WEF poller on the leader loop behind `OPENSHIELD_WEF_DIR`.
- No migration (reuses `external_logs`), no proto/core change, no new dependency (encoding/xml only).
