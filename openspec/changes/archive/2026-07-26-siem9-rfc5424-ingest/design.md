## Context

`internal/connectors/syslog` already handles RFC 5424 FRAMING and deliberately strips structured data so
`Msg` is free text. CEF ingest sits on top of it. The gap is structured data as fields.

## Goals / Non-Goals

**Goals:** an RFC 5424 parser with structured data; one listener for both formats; SD huntable as fields.

**Non-Goals:** JSON-lines, GELF, cross-vendor field normalization, a unified severity scale.

## Decisions

### A separate parser, not an extension of the framing layer

The framing layer's job is to produce a free-text message, and it is right to strip SD for that. Teaching
it a second job — keep the SD, but only for some callers — would make one parser serve two contracts. So
the raw line is carried through and re-parsed by a package whose contract is the structured one.

### CEF first

A CEF payload normally arrives inside an RFC 5424 frame, so a line is often valid as both. The CEF reading
is the more specific one, and an existing end-to-end test uses exactly that shape — which is what makes
the ordering load-bearing rather than arbitrary. Reversing it breaks that test.

### Flatten SD to `sdid.key`

The destination is a flat JSONB map queried with `fields->>'key'`. Preserving the nesting here would only
mean flattening it later, somewhere with less context about the format.

### Hand-written value parsing, not a regex

Inside an SD value, `\"`, `\\` and `\]` are escapes. A regex that missed them truncates a value at the
first quoted bracket — silently, and only for the messages that contain one.

### The counter is documented, not renamed

`CEFDropped` widened from "was not CEF" to "parsed as neither". Renaming it would break every dashboard
built on `openshield_cef_dropped_total`, so the meaning is corrected where it is defined and in the metric
help text. A pre-existing test caught the widening: its "non-CEF" fixture was a valid RFC 5424 line and so
became ingested. The assertion was right; the fixture was what had to change.

## Risks / Trade-offs

- **Severity scales differ** → the RFC's numeric level maps to its own standard label and is NOT reconciled
  with CEF's 0–10. Inventing a shared scale would make a cross-source severity filter quietly wrong.
- **Field names are not normalized** → an SD key and a CEF key are both huntable under their own names;
  normalizing is a separate decision about whose vocabulary wins.

## Migration Plan

Additive. A deployment sending only CEF is unaffected except that previously-dropped RFC 5424 lines are now
ingested — which is the point, and is visible as ingest rising and drops falling.

## Open Questions

- Whether JSON-lines should reuse this listener or take its own port, since it has no syslog framing.
