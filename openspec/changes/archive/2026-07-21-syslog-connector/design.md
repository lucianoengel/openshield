## Context

The DNS (D101) and SMTP (D102) connectors established the pattern: a pure protocol parser,
sockets deferred. Syslog is the same for external log ingest.

## Goals / Non-Goals

**Goals:** parse RFC 5424 + RFC 3164 syslog into a structured record; bounded; reject
non-syslog.

**Non-Goals:** the socket listener; SD key/value indexing; TLS framing (RFC 5425).

## Decisions

**Priority is the one required field.** Every syslog message begins with "<PRI>"; PRI =
facility*8 + severity, validated 0..191. A line with no valid priority is rejected — it is
not syslog, and accepting it would let arbitrary text pollute the ingest. Everything after
the priority is best-effort structured (a truncated header yields what was present), because
real-world syslog is famously inconsistent and dropping a whole line over a missing optional
field would lose the event.

**Two formats, auto-detected.** RFC 5424 is detected by the version digit "1" right after
the PRI; otherwise the BSD RFC 3164 shape is assumed. 5424 structured-data is skipped by a
bracket-balanced walk so a message is the free text, not the "[sd...]" prefix — the test
includes SD with internal spaces to prove the walk, not a naive split.

## Risks / Trade-offs

- **Best-effort field parsing.** The formats are loose in practice; the parser favors
  extracting what it can over strict rejection (except the priority). A field that a
  malformed source mangles becomes empty, not an error — the message still ingests.
- **Parser only.** The 514 listener is the external-gated data-plane half, deferred with its
  privileges as with DNS/SMTP; classifying the message text composes with the classifier.
