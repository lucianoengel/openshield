## Context

D205/D208 established the external-log ingest shape (a parser → the `external_logs` store → the `/logs`
query, D210). CloudTrail added a directory poller with `.ingested`/`.failed` rename idempotency. WEF is
the Windows format: a Windows Event Collector forwards events as the standard Windows Event XML, and the
common on-prem export is a directory of `.xml` files. WEF is structurally the same ingest problem as
CloudTrail (parse a file → persist records → mark processed), so it shares the poller and differs only
in the parser + the field mapping.

## Goals / Non-Goals

**Goals:**
- Faithfully parse Windows Event XML into structured fields over its fixed schema.
- Ingest WEF files into the existing `external_logs` store, idempotently, reusing the CloudTrail poller.
- Searchable via the same `/logs` endpoint (vendor=microsoft) — one external-log surface, three sources.
- Prove parser + ingest on real XML + real Postgres, mutation-verified. No regression to CloudTrail.

**Non-Goals:**
- A live WS-Management / WEF subscription endpoint (the collector's job; the directory is the handoff).
- EVTX binary log parsing (WEF forwards XML; a native EVTX reader is a separate connector).
- Mapping every EventData field into columns — the fixed subset is columnised, the full event XML stays
  in `raw` for follow-on field-level hunting (matches CEF/CloudTrail).
- Windows AGENTS (PLAT-7, procurement-gated) — WEF ingest needs no OpenShield agent on Windows; it
  parses what a WEC already forwards.

## Decisions

1. **Streaming XML scan for `<Event>` elements.** `Parse` uses `xml.Decoder` and scans tokens for
   `<Event>` start elements, `DecodeElement`-ing each — so it handles a single `<Event>` root, an
   `<Events>…</Events>` wrapper (the standard export), and namespaced documents uniformly (Go's
   encoding/xml matches on local name). This avoids assuming one specific wrapper. Malformed XML surfaces
   as the decoder's error (not a partial record).

2. **Fixed-schema `Record`.** From `<System>`: EventID, Provider Name, Level, TimeCreated SystemTime,
   Computer, Channel. From `<EventData>`: the `Data` Name/Value pairs (kept as a map). A record with no
   EventID has no event identity → counted-skipped, never a partial row. A 32 MiB delivery bound stops
   an exhaustion file.

3. **Map onto the shared `ExternalLog`.** vendor="microsoft", product="windows", signature_id=EventID,
   name = Provider + "/" + EventID, severity = Level, source_host = Computer, received_at = TimeCreated,
   message = a compact summary (provider, channel, and a couple of common EventData keys like
   TargetUserName/IpAddress when present), raw = the event XML. So `/logs?vendor=microsoft` returns
   Windows events beside `?vendor=aws` (CloudTrail) and the CEF vendors.

4. **Extract the poller into `scanIngestDir`.** The scan + rename-on-success/`.failed`-on-error logic is
   format-agnostic. Extract it from `scanCloudTrailDir` into `scanIngestDir(ctx, dir, isTarget, ingestOne)`
   and have BOTH CloudTrail and WEF use it. CloudTrail's existing tests (persist+idempotent, poison-file)
   verify the refactor is behavior-preserving. Per-format drop counting stays in each `ingestOne`.

5. **Leader-only, env-gated.** `RunWEFIngest` runs under `leaderCtx` behind `OPENSHIELD_WEF_DIR`, exactly
   like the CEF/CloudTrail ingest — only the leader ingests, a scan error is logged, never fatal.

## Risks / Trade-offs

- **XML is fiddlier than JSON.** Mitigated by the streaming scan (tolerant of wrapper/namespace variation)
  and thorough tests over real Windows Event XML (single event, `<Events>` batch, missing EventID,
  malformed). Go's `encoding/xml` is the standard-library parser — no new dependency, no custom lexer.
- **Directory delivery, not a live subscription.** Deliberate: the WEC owns the WS-Man subscription; a
  spool directory is the standard handoff and needs no Windows-side OpenShield component.
- **Refactoring the working CloudTrail poller.** Low risk — the extraction is mechanical and CloudTrail's
  tests gate it; the parse/map logic (the part that could subtly differ) is untouched.
