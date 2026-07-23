## Context

D205 established the external-log ingest shape: a hardened receiver hands a parsed record to a persist
sink that writes the `external_logs` store (structured columns + raw, kept SEPARATE from verified agent
telemetry). CEF-over-syslog was the first format. CloudTrail is the cloud-audit format: a delivery is a
JSON object `{"Records":[{...}, ...]}`, each record a well-documented event. Delivery is S3-based, so
the common on-prem pattern is an S3 bucket synced to a local directory (aws s3 sync / a sidecar).

## Goals / Non-Goals

**Goals:**
- Faithfully parse CloudTrail JSON into structured fields over its FIXED schema (no field-guessing).
- Ingest delivered CloudTrail files into the existing `external_logs` store, idempotently.
- Reuse the store + search from D205; add no new table.
- Prove the whole path on real files + real Postgres, mutation-verified.

**Non-Goals:**
- WEF (Windows XML) — a separate parser, same pattern, later.
- S3/SQS clients — the directory (S3-synced) is the delivery point; a native S3 poller is a follow-on.
- Mapping every CloudTrail field into columns — the fixed security-relevant subset is columnised; the
  full record is kept in `raw` for follow-on field-level hunting (matches D205).
- Correlating cloud events into incidents (XDR-4 lane).

## Decisions

1. **Pure parser + a fixed-schema `Record`.** `Parse` decodes `{"Records":[…]}` and each record's
   documented fields. It is a faithful decoder (D4) — it does NOT interpret (severity meaning, which
   events are "bad" is the policy/detector's job). Unknown extra fields are ignored (forward-compatible);
   a delivery that is not JSON or has no `Records` array is an error; a record missing required identity
   (no eventName) is counted as skipped, not a partial row. A 32 MiB delivery bound (a CloudTrail file
   is many small records) prevents a memory-exhaustion file.

2. **Map a Record onto the existing `ExternalLog`.** vendor="aws", product="cloudtrail",
   signature_id=eventName, name=eventName, severity=errorCode (empty = success), source_host =
   sourceIPAddress (the actor's IP — a hunting pivot), message = eventSource + ":" + eventName,
   received_at = eventTime, raw = the record's JSON. So cloud events are searchable by the SAME
   `SearchExternalLogs` (vendor="aws") the CEF path uses — one external-log surface, many sources.

3. **Directory poller with rename-based idempotency.** `RunCloudTrailIngest` polls `dir` on a ticker;
   for each `*.json`/`*.json.gz` (a `.gz` is gunzipped, bounded), it parses, inserts every record, then
   renames the file to `*.ingested`. A file that fails to read/parse/persist is renamed `*.failed` and
   counted — so a poison file neither blocks the directory nor retries forever, and a restart re-scans
   only un-suffixed files (idempotent: an already-ingested file was renamed, so it is not re-ingested).
   A `.json` file is assumed COMPLETE (the standard forwarder writes to a temp name and renames on
   completion); a partial file that fails to parse becomes `.failed` and can be re-dropped.

4. **Leader-only, env-gated.** Runs under `leaderCtx` behind `OPENSHIELD_CLOUDTRAIL_DIR`, like
   RunCEFSyslog — only the leader ingests, so failover does not double-store; a scan error is logged,
   never fatal.

## Risks / Trade-offs

- **Directory delivery, not native S3.** Deliberate: it needs no AWS SDK/credentials in the server and
  works with any sync tool. A native S3/SQS poller is a follow-on for shops that prefer it.
- **Rename requires write access to the drop directory.** Standard for a spool dir; documented. If the
  dir is read-only, ingest logs the rename failure and (to avoid a re-ingest loop) skips the file — a
  known limitation surfaced, not silent.
- **CloudTrail's own eventTime is the source clock.** Stored as `received_at` for time-window search
  (the record's authoritative time); unlike syslog we trust CloudTrail's timestamp because the delivery
  is the audit record itself. The ingest time is not separately kept (a follow-on if needed).
