## Context

`external_logs` (D205) stores fixed columns + `raw` (the original event text). The three parsers each
already produce a per-event key/value map (CEF `Extensions`, WEF `EventData` `Data`, CloudTrail's fixed
fields), but the mappers only pulled a few into columns and dropped the rest into `raw`. So the data
exists at ingest — it just is not stored queryably.

## Goals / Non-Goals

**Goals:**
- Store every parsed per-event field structured, so an analyst can hunt on any of them.
- One field filter that works across ALL sources (a `sourceIPAddress`/`IpAddress` pivot spans CloudTrail
  and WEF).
- Keep it additive: existing columns, `raw`, and the existing filters are unchanged.

**Non-Goals:**
- Full-text search over `raw` (a JSONB exact/containment match on parsed fields is the target; free-text
  is a separate follow-on, e.g. tsvector).
- Normalizing field NAMES across vendors (CloudTrail `sourceIPAddress` vs WEF `IpAddress` stay as the
  source emits them; a cross-vendor field taxonomy is a bigger XDR-normalization concern).
- Multiple field filters in one query (a single `key:value` is the first cut; repeated params later).

## Decisions

1. **`fields JSONB`, not more columns.** The field set is open-ended and vendor-specific, so a JSONB
   object is the right shape (a column per possible key is unbounded). A GIN index makes
   containment/`->>' '` lookups fast. Default `'{}'` so existing rows and non-field inserts are valid.
   The column inherits `external_logs`' writer-role grant (no new grant).

2. **Mappers fill `Fields` from their existing maps.** CEF → `msg.Extensions`; WEF → `rec.Data`;
   CloudTrail → a small map of its parsed fields (eventSource, actor arn, region, account, errorCode) so
   cloud events are huntable too. `raw` still holds the full original for anything not mapped.

3. **`fields->>$key = $value` for the filter.** The JSONB `->>` operator takes the key as a bind param,
   so `WHERE fields->>$N = $M` is a parameterized exact match — no SQL-injection surface, and the GIN
   index (plus a btree on the expression if needed) serves it. An exact match is the common hunt
   ("this user", "this IP"); ranges/globs are a follow-on.

4. **`?field=key:value` on `/logs`, 400 on malformed.** A single `field` param split on the first `:`
   into key/value; an empty key or a missing `:` is a 400 (SEC-8) — a silently-ignored field filter
   returns over-broad results an investigator would trust. Consistent with the existing since/until/limit
   validation.

## Risks / Trade-offs

- **A JSONB column + GIN index adds write cost.** External-log ingest is bounded (batched files /
  syslog), and the index speeds the hunt that is the whole point. Acceptable.
- **Field names are as-emitted (not normalized).** Deliberate (see non-goals) — normalizing is an XDR
  concern; here the raw source field names are the honest, lossless representation. Documented.
- **A migration on a table that may hold rows.** `ADD COLUMN ... DEFAULT '{}'` is safe and fast on
  Postgres (a metadata-only default in PG 11+); existing rows read `{}` (no fields) until re-ingested,
  which is correct — old rows simply have no structured fields.
