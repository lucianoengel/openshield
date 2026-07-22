## Context

D202 gave a pure CEF parser; `internal/connectors/syslog` gives a hardened UDP listener
(`syslog.Listen(addr, sink, logger)`, bounded line, rate-limited, panic-recovering) whose `sink`
receives a parsed `syslog.Message` with a free-text `Msg`. CEF is carried INSIDE that free text:
`<PRI>timestamp host CEF:0|vendor|product|...`. So the composition is: syslog datagram → `syslog.Parse`
→ take `Msg` → find the `CEF:` payload → `cef.Parse` → persist. Nothing runs this today, and there is no
store for external logs — both are this ticket.

## Goals / Non-Goals

**Goals:**
- Receive CEF-over-syslog on a real socket and persist each parsed event as a searchable row.
- Reuse the existing hardened syslog listener (do not write a second UDP loop or a second bounds/limiter).
- Keep the parser untouched; add only the extractor, the store, and the wiring.
- Prove the whole path end-to-end on a real socket + real Postgres, mutation-verified.

**Non-Goals:**
- A general syslog store (non-CEF lines are counted + skipped here; storing raw syslog is a follow-on).
- WEF/cloud-JSON ingest (separate parsers, D202 note).
- An HTTP `/logs` endpoint (the `SearchExternalLogs` store method is the query capability; a handler
  mirroring `/events` is a trivial follow-on).
- Correlating external logs into incidents (that is the XDR-2/4 lane once the entity model spans them).

## Decisions

1. **`FromSyslog(msg string) (cef.Message, bool)`** locates the `CEF:` marker in the syslog free text and
   parses from there. It returns `(_, false)` when there is no CEF payload — a NON-error, so a mixed
   stream (some CEF, some plain syslog) is handled by the caller counting skips, not by treating a plain
   line as malformed. A present-but-malformed CEF payload returns `(_, false)` too (the parser's error is
   the reason it is not ingested); the listener counts it as dropped. Extraction is a substring search
   for `"CEF:"` (the format's fixed marker); everything from there is handed to the unchanged `cef.Parse`,
   which enforces the `CEF:` prefix + 7 headers + the 64 KiB bound.

2. **`external_logs` table** stores the structured header fields as columns (queryable) + the raw line
   (fidelity). Extensions are NOT exploded into columns in this ticket (CEF extension keys are open-
   ended); the raw line preserves them and field-level extension hunting is a follow-on (matches the
   SIEM status: `payload` field-level hunting is separately tracked). The table auto-grants to the
   non-owner writer role via migration 017's default privileges (like `ueba_baselines`), so no explicit
   grant migration is needed.

3. **`RunCEFSyslog(ctx, addr)` lives on the control-plane Server**, composing `syslog.Listen` with a sink
   that `FromSyslog`s and `InsertExternalLog`s. It runs in the leader loop (only the leader ingests, so
   two servers do not double-store), gated by `OPENSHIELD_CEF_SYSLOG_LISTEN`. A persist error is counted
   (`CEFDropped`) and logged, never crashes the listener — ingest availability over completeness for a
   best-effort external feed, consistent with the connector's existing drop-counting.

4. **Bounded search.** `SearchExternalLogs(filter)` supports time window + vendor/product/host/severity
   equality + a capped limit (reusing the `maxSearchLimit` discipline from `/events`), newest first. It
   is the query capability the follow-on HTTP handler will expose.

## Risks / Trade-offs

- **UDP syslog is unauthenticated and spoofable.** That is inherent to syslog ingest; external logs are
  explicitly UNVERIFIED (unlike signed agent telemetry) and stored in a SEPARATE table so they are never
  confused with attributable telemetry. The store records the source host as reported — a hunting aid,
  not an attestation. TLS syslog (RFC 5425) is a follow-on.
- **Extensions not columnised.** Deliberate (open-ended keys); the raw line keeps them for follow-on
  field-level hunting. Documented, not silently dropped.
- **Only the leader ingests.** A standby does not receive datagrams; on failover the new leader starts
  listening. A brief gap at failover is acceptable for a best-effort log feed (senders retransmit or the
  gap is a known window), and it avoids double-storing.
