## Why

SIEM-4 shipped the CEF parser (D202) and the CEF-over-syslog listener + `external_logs` store (D205),
and its scope note names the remaining formats: "WEF (Windows Event Forwarding XML) + cloud-JSON are
separate parsers reusing this connector pattern." The estate's CLOUD control plane (AWS/GCP/Azure) is a
primary source of security-relevant events — an assumed-role escalation, a disabled CloudTrail, a
public-S3 change — and it speaks JSON, not CEF-over-syslog. Today those events land nowhere. This adds
the canonical cloud-audit format, **AWS CloudTrail**, so the SIEM ingests the cloud, not only the
endpoint and network.

## What Changes

- **A CloudTrail JSON parser** (`internal/connectors/cloudtrail`): `Parse(jsonBytes) → []Record` decodes
  a CloudTrail delivery (`{"Records":[ … ]}`) into the fixed, documented fields (eventTime,
  eventSource, eventName, awsRegion, sourceIPAddress, userIdentity.arn, errorCode, recipientAccountId).
  A faithful decoder over a FIXED schema — no heuristic field-guessing (the "verifies against its own
  assumptions" trap). A body that is not a CloudTrail delivery (not JSON, no `Records`) is an error, and
  a single malformed record is counted, not silently dropped.
- **A directory-poller ingest** (`Server.RunCloudTrailIngest(ctx, dir)`): CloudTrail is delivered to S3
  and commonly synced to a local directory; the poller ingests each new `*.json`/`*.json.gz` file,
  persists its records into the existing `external_logs` store (vendor=aws, product=cloudtrail), and
  renames the file to `*.ingested` so a restart does not re-ingest (idempotent). A bad file is counted
  and renamed `*.failed`, never re-tried forever or left to block the directory.
- **Wired into the server leader loop** behind `OPENSHIELD_CLOUDTRAIL_DIR` (leader-only, so a
  multi-instance deployment does not double-ingest), reusing the D205 `external_logs` store and its
  bounded search.

No new store, no new proto, no new dependency — this composes a new parser with the existing
external-log store and search.

## Capabilities

### New Capabilities
- `cloudtrail-ingest`: parsing AWS CloudTrail JSON deliveries and persisting each event as a searchable
  external-log record, so cloud control-plane activity is queryable beside endpoint and network events.

### Modified Capabilities
<!-- none: reuses the external-log store; the cef-syslog-ingest capability is unchanged. -->

## Impact

- `internal/connectors/cloudtrail`: `Parse` + `Record` + a bound on delivery size.
- `internal/controlplane`: `RunCloudTrailIngest(ctx, dir)` + `CloudTrailIngested`/`CloudTrailDropped`
  counters; maps a Record onto the existing `ExternalLog`/`InsertExternalLog`.
- `cmd/openshield-server`: run the poller on the leader loop behind `OPENSHIELD_CLOUDTRAIL_DIR`.
- No migration (reuses `external_logs`), no proto/core change, no new dependency.
