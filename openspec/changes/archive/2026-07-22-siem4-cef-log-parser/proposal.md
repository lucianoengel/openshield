## Why

OpenShield ingests its own signed telemetry and raw syslog, but a SIEM must consume the *structured*
security logs the rest of the estate emits — firewalls, IDS, WAFs, endpoint tools — and the lingua franca
for those is **CEF (ArcSight Common Event Format)**. Without a CEF parser, those events arrive (over
syslog) as opaque free text: their vendor, signature, severity, and rich key=value extension are
invisible to search and correlation. This adds CEF parsing — the untrusted-bytes surface handled and
tested in plain Go, exactly like the syslog/DNS/SMTP parsers — so third-party security events become
structured records.

## What Changes

- A `cef` connector: `Parse(line)` decodes a CEF message — the seven pipe-delimited header fields
  (version, vendor, product, device-version, signature id, name, severity) and the `key=value` extension
  — honoring CEF's escaping rules (`\|` in headers; `\=`, `\\`, `\n` in extension values).
- A malformed CEF line is an error, never a partial record silently treated as complete (D17) — a log
  ingest that quietly mangles lines is a blind spot.

## Capabilities

### New Capabilities
- `cef-ingest`: parse third-party security events in ArcSight CEF into structured records (vendor,
  product, signature, severity, and the key=value extension), so external security logs are searchable
  and correlatable — the format that makes OpenShield a SIEM consuming the estate, not only itself.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** a new `internal/connectors/cef` package (a pure parser + a bounded line limit), no proto/core
  change. Proven: a canonical CEF line parses to its seven headers and extension map; escaped pipes in
  headers and escaped `=`/`\`/newlines in extension values are decoded correctly; a value containing
  spaces is kept whole (up to the next key); a line without the `CEF:` prefix or with too few header
  fields is rejected; an oversized line is rejected.
- **Scope note (honest):** this increment is the CEF PARSER (the untrusted-bytes surface), the same first
  step syslog took. Wiring parsed CEF into a live listener and PERSISTING it into the verified
  search/correlation path is the ingest-plumbing follow-on (CEF is typically carried over syslog, so it
  composes with the existing syslog listener). **WEF (Windows Event Forwarding XML) and cloud-JSON
  formats** are separate parsers reusing this connector pattern, noted.
