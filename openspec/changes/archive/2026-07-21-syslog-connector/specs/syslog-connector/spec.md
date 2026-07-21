# syslog-connector delta

## ADDED Requirements

### Requirement: The syslog connector parses RFC 5424 and RFC 3164 messages, rejecting non-syslog
The connector MUST parse a syslog line's priority into facility and severity, and extract
the timestamp, host, application, and message across both RFC 5424 (skipping structured
data) and RFC 3164 formats, bounded against an oversized line. A line without a valid
priority — the one field every syslog message carries — MUST be rejected, never returned as
a partial record. The facility/severity split MUST follow PRI = facility*8 + severity across
the full range.

#### Scenario: A valid message parses and a non-syslog line is rejected
- **WHEN** the connector parses a syslog line
- **THEN** a valid RFC 5424 or 3164 message yields its facility, severity, host, app, and message (structured data skipped), and a line with no valid priority is rejected
