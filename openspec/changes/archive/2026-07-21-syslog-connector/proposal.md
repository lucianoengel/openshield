## Why

OpenShield's telemetry was its own signed fleet stream. Phase F5 adds third-party log
ingest — parsing RFC 5424 and RFC 3164 syslog — the step that lets it consume EXTERNAL
sources and become a SIEM, not just an audit of itself.

## What Changes

- `internal/connectors/syslog`: `Parse` — decodes a syslog line's priority
  (facility/severity), timestamp, host, app, and message across RFC 5424 (with
  structured-data skipping) and RFC 3164 (BSD); bounded; rejects a line with no valid
  priority.

## Capabilities

### Added Capabilities
- `syslog-connector`: third-party syslog lines are parsed into structured records.

## Impact

- New `internal/connectors/syslog`; `docs/decisions.md` D106.
- Proven with real syslog lines: an RFC 5424 message decodes to facility/severity 4/2, host,
  app, message (with structured-data skipped even when it contains spaces); an RFC 3164 BSD
  line decodes host/tag/message; priority splits exactly across the range (0→0/0, 191→23/7,
  86→10/6); malformed lines (empty, no priority, no opening '<', unclosed, non-numeric,
  out-of-range) are rejected. Guards mutation-tested (priority-range; facility/severity-
  split; SD-stripping; missing-'<').
- NOT in scope (stated): the UDP/TCP:514 socket listener (the I/O side, as with DNS/SMTP —
  a pure parser here, the listener is external-gated data-plane); classifying the message
  text for PII (the parsed Msg can be fed to the classifier — a composition follow-up like
  SMTP's body); full RFC 5424 structured-data key/value extraction (skipped, not indexed);
  RFC 5425 (TLS) framing. A malformed line is an error, never a silently-dropped/mangled
  record (D17). No core change (a new connector — D26 pattern).
