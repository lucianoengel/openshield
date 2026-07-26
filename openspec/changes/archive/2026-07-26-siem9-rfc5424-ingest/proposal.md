## Why

The syslog listener ingests CEF only. Most of an estate that is *not* emitting CEF emits **RFC 5424** —
modern syslog — and its `[id key="value"]` **structured data** maps directly onto the `fields` JSONB that
already backs cross-source hunting. Without it, an operator either runs a second collector or does not
onboard those sources at all, and a source that is never onboarded is a detection gap that looks like a
configuration choice.

Worth being precise about what was already there: `internal/connectors/syslog` **already parses RFC 5424
framing** — it deliberately *discards* the structured data to leave the message as free text. What was
missing is that structured data as searchable fields.

## What Changes

- `internal/connectors/rfc5424`: a pure parser producing the header plus **flattened `sdid.key` → value**
  structured data.
- **One listener, both formats.** CEF is tried first because a CEF payload normally arrives *inside* an
  RFC 5424 frame — a line can legitimately be both, and the CEF reading is the more specific one.
- `syslog.Message` gains `Raw`, because the framing layer strips structured data by design and the fields
  this exists to capture are therefore not in `Msg` at all.
- **A widened counter, documented rather than renamed.** `CEFDropped` now means "parsed as neither format",
  not "was not CEF". The names stay because they are on `/metrics` and renaming breaks dashboards; the
  meaning is corrected in the help text and at the definition.

## Capabilities

### Modified Capabilities
- `cef-syslog-ingest`: the listener accepts RFC 5424 alongside CEF, with structured data huntable as fields.

## Impact

- **New**: `internal/connectors/rfc5424`. **Changed**: the listener, `syslog.Message`, counter docs.
- **No migration, no proto change, no new dependency.**
- **Honest scope**: JSON-lines and GELF remain in SIEM-9 and are not in this change. No cross-vendor field
  normalization — an SD key and a CEF key are both huntable but keep their own names, and normalizing them
  is a separate decision about whose vocabulary wins. Severity is the RFC's numeric level mapped to its
  standard label; it is NOT reconciled with CEF's 0–10 scale, because inventing a shared scale would make
  a cross-source severity filter quietly wrong.
