# syslog-connector Specification

## Purpose
A third-party log-ingest connector that parses RFC 5424 and RFC 3164 (BSD) syslog messages into structured records (priority → facility/severity, timestamp, host, application, message), so OpenShield can ingest external log sources and act as a SIEM over more than its own signed telemetry. It is a pure parser; the 514 socket listener is a separate, external-gated data-plane concern.

## Requirements

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

### Requirement: The syslog connector runs a UDP listener that survives malformed input
The syslog connector MUST provide a UDP listener that binds a configurable address, parses
each received datagram, and delivers the parsed message to a sink. A datagram that fails to
parse MUST be dropped and counted, never stopping the receive loop, and the drop count MUST
be observable. The listener MUST shut down cleanly on context cancellation, and MUST refuse
a nil sink.

#### Scenario: Valid datagrams are delivered and garbage is dropped
- **WHEN** the listener receives valid and malformed syslog datagrams
- **THEN** the valid ones are parsed and delivered, the malformed one is dropped and counted, ingest keeps running, and the listener stops cleanly when cancelled
