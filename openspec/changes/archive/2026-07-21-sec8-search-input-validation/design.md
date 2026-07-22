## Context

The /search handler parsed params with "if it parses, use it; else ignore" — a silent drop
that turns a typo into an over-broad, authoritative-looking result.

## Goals / Non-Goals

**Goals:** 400 on a malformed filter; a hard limit cap.

**Non-Goals:** configurable cap; pagination.

## Decisions

**Malformed is a 400, not a silent drop.** `parseAlertFilter` returns an error for any param
that does not parse, and the handler answers 400. An investigator must not silently receive a
broader result than they asked for — the error-vs-silent-default honesty rule applied to HTTP
input.

**Limit is clamped, not rejected.** An oversized limit is honored up to `maxSearchLimit`
rather than 400'd — a big ask is reasonable, an unbounded one is not. Clamped in the parser
AND in SearchPeerAlerts, so a direct (non-HTTP) caller cannot blow past it either.

## Risks / Trade-offs

- **The cap is hard-coded** (1000). A config surface is PLAT-5; 1000 is a safe default for the
  current fleet scale.
