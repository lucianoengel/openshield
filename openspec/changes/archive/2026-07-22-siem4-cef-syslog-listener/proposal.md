## Why

SIEM-4 shipped the CEF *parser* (D202) — a faithful decoder of ArcSight Common Event Format — but its
own scope note names the follow-on: "a live LISTENER + PERSISTING parsed CEF into the search/correlation
path". Today NOTHING runs it: the CEF parser and the syslog listener both exist, but no binary receives
external logs, and there is no store for them. So OpenShield is a SIEM that consumes only its OWN signed
telemetry — the estate's firewalls/IDS/WAFs/endpoint tools speak CEF over syslog and their events land
nowhere. This ticket closes the ingest plumbing: receive CEF-over-syslog, persist the structured record,
and make it queryable.

## What Changes

- **CEF-from-syslog extraction** (`internal/connectors/cef`): `FromSyslog(syslogMsg)` finds and parses a
  CEF payload embedded in a syslog message's free text (CEF rides syslog — the syslog header is stripped
  by the existing `syslog.Parse`, and the `CEF:` payload is what remains). A message with no CEF payload
  is reported as such (not an error), so a mixed syslog stream is handled cleanly.
- **External-log store** (`internal/store/postgres`): a new `external_logs` table and
  `InsertExternalLog` / `SearchExternalLogs` — structured columns (received-at, source host, vendor,
  product, signature id, name, severity, message) plus the raw line, with a bounded, filtered search.
- **A runnable CEF-over-syslog listener** wired into the control-plane server's leader loop, gated by
  `OPENSHIELD_CEF_SYSLOG_LISTEN`: it composes the existing `syslog.Listener` with `FromSyslog` and a
  persisting sink, so a CEF datagram becomes a searchable external-log row. Non-CEF syslog lines are
  counted and skipped (this listener's job is CEF; a general syslog store is a separate follow-on).

The parser is unchanged (D202); this composes it with the existing hardened syslog listener (bounded
line size, rate limiting, panic recovery) and adds persistence — no new untrusted-bytes surface beyond
what those two already handle and test.

## Capabilities

### New Capabilities
- `cef-syslog-ingest`: receiving CEF-over-syslog from the estate, persisting each parsed event as a
  searchable external-log record, so OpenShield ingests third-party security logs, not only its own
  telemetry.

### Modified Capabilities
<!-- none: the cef-ingest (parser) capability's requirements are unchanged; this adds the listener +
     persistence around it. -->

## Impact

- `internal/connectors/cef`: `FromSyslog` extractor (+ a `hasCEF` boundary helper).
- `internal/store/postgres`: migration `022_external_logs.sql`, `ExternalLog` type,
  `InsertExternalLog`, `SearchExternalLogs` + an `ExternalLogFilter`.
- `internal/controlplane`: a `RunCEFSyslog(ctx, addr)` that runs the listener with a persisting sink +
  a `CEFIngested`/`CEFDropped` counter; a `SearchExternalLogs` pass-through.
- `cmd/openshield-server`: wire `RunCEFSyslog` into the leader loop behind `OPENSHIELD_CEF_SYSLOG_LISTEN`.
- No proto change, no core change, no new dependency. The `external_logs` table auto-grants to the
  non-owner writer role (migration 017 default privileges). An HTTP `/logs` query surface is a small
  noted follow-on (the `SearchExternalLogs` method is the query capability).
