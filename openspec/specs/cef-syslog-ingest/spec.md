

## Purpose

Third-party log ingest over syslog: a live listener that accepts CEF and RFC 5424, extracts their fields
into structured, searchable columns rather than an opaque blob, and COUNTS the lines neither parser
accepts instead of storing or discarding them silently. This is what makes the platform a SIEM over the
estate's logs rather than a store of only its own telemetry.

## Requirements

### Requirement: The listener accepts RFC 5424 alongside CEF

One listener SHALL ingest both CEF and RFC 5424 syslog. Requiring a separate collector per format is how a
log source ends up not onboarded, which is a detection gap that presents as a configuration choice.

CEF SHALL be attempted first: a CEF payload is normally carried inside an RFC 5424 frame, so a line can be
both, and the CEF reading is the more specific one.

#### Scenario: A modern-syslog line is ingested
- **WHEN** an RFC 5424 line arrives that is not CEF
- **THEN** it is stored with its host, app, severity and message

#### Scenario: CEF inside an RFC 5424 frame is still read as CEF
- **WHEN** a line is valid as both
- **THEN** it is stored as the CEF record

### Requirement: Structured data is huntable like a CEF extension

RFC 5424 structured-data elements SHALL be stored in the same per-event field map CEF extensions use, so a
single query shape hunts across both sources.

#### Scenario: An SD parameter is searchable
- **WHEN** a line carries `[id key="value"]`
- **THEN** a field search for that key and value returns it

### Requirement: A line neither parser accepts is counted, not stored

A datagram that parses as neither format SHALL be counted and discarded, never stored as a partial record.
A log ingest that quietly stores mangled lines is a blind spot that looks like coverage.

#### Scenario: Unparseable input is dropped and counted
- **WHEN** a datagram matches neither format
- **THEN** the drop counter increases and no record is stored

### Requirement: Per-event fields are stored structured and searchable

The system SHALL store each ingested external log's parsed per-event fields (CEF extensions, WEF
EventData, CloudTrail's parsed fields) as a structured JSON object, and SHALL support searching external
logs by an exact match on any such field, across all sources. A malformed field-filter syntax SHALL be
rejected (a 400 on the query surface), not silently ignored.

#### Scenario: An analyst hunts by a parsed field
- **WHEN** external logs from different sources are ingested and a search filters on a field key=value present in some of them
- **THEN** only the logs whose parsed fields contain that exact key=value are returned

#### Scenario: The same field pivots across sources
- **WHEN** a source IP appears as a parsed field in both a CloudTrail and a WEF event
- **THEN** a single field search on that IP returns both

#### Scenario: A malformed field filter is rejected
- **WHEN** a `/logs` field filter has no key or is not `key:value`
- **THEN** the request is a 400, not an over-broad result

<!-- restored from 2026-07-22-siem-field-level-hunting -->

### Requirement: CEF extraction from a syslog message

The system SHALL extract and parse a CEF payload carried inside a syslog message's free text. A message
containing a valid CEF payload SHALL yield the parsed CEF fields; a message with no CEF payload, or with
a malformed CEF payload, SHALL be reported as "no CEF" rather than an error, so a mixed syslog stream is
handled without treating a plain line as a failure.

#### Scenario: A CEF-over-syslog line is parsed
- **WHEN** a syslog message whose free text contains `CEF:0|Vendor|Product|1.0|100|Worm blocked|8|src=10.0.0.1`
- **THEN** extraction returns the CEF fields (vendor "Vendor", product "Product", signature id "100", …)

#### Scenario: A non-CEF syslog line is skipped
- **WHEN** a syslog message whose free text carries no `CEF:` payload
- **THEN** extraction reports "no CEF" and no record is produced

<!-- restored from 2026-07-22-siem4-cef-syslog-listener -->

### Requirement: External-log persistence and search

The system SHALL persist each parsed CEF event as an external-log record with its structured header
fields, source host, receipt time, and raw line, and SHALL provide a bounded, filtered search over
those records (time window, vendor/product/host/severity, capped limit, newest first). External logs
SHALL be stored separately from attributable signed telemetry so an unverified third-party log is never
confused with verified agent telemetry.

#### Scenario: A parsed CEF event is stored and found
- **WHEN** a CEF external log is inserted
- **THEN** a search matching its vendor within the time window returns that record with its fields intact

#### Scenario: Search is bounded
- **WHEN** a search requests more than the maximum allowed results
- **THEN** the result set is capped at the maximum

<!-- restored from 2026-07-22-siem4-cef-syslog-listener -->

### Requirement: A live CEF-over-syslog listener

The system SHALL run a listener that receives CEF-over-syslog datagrams and persists each parsed event
as a searchable external-log record. A datagram that is not CEF, or whose persistence fails, SHALL be
counted (not silently dropped) and SHALL NOT crash the listener. The listener SHALL run only on the
elected leader so a multi-instance deployment does not double-store.

#### Scenario: A CEF datagram is received and becomes searchable
- **WHEN** the listener receives a CEF-over-syslog datagram
- **THEN** the parsed event is persisted and appears in an external-log search

#### Scenario: A malformed datagram does not stop ingest
- **WHEN** the listener receives a non-CEF or malformed datagram
- **THEN** it is counted as skipped/dropped and the listener continues serving subsequent datagrams

<!-- restored from 2026-07-22-siem4-cef-syslog-listener -->

### Requirement: External log ingest offers a transport that does not lose events silently

The system SHALL accept estate logs over a STREAM transport in addition to datagrams, so that a receiver
which cannot keep up applies backpressure to its senders rather than discarding events.

Datagram ingest SHALL remain available for devices that cannot do better, and SHALL be documented as
best-effort and NOT evidentiary. Its loss is invisible by construction: a datagram the kernel discards
for want of buffer never reaches the application, so no counter the application keeps can observe it.

The stream transport SHALL accept both framings that real senders emit — octet-counted and
newline-terminated — because requiring one of them is how a log source ends up not onboarded.

**Honest limit, which SHALL be stated wherever the guarantee is described:** a stream transport removes
kernel-level silent drop and adds backpressure. It does NOT acknowledge PERSISTENCE, so a receiver killed
with buffered data still loses it. The claim is that loss requires a crash or an explicit refusal — both
observable — rather than a buffer quietly filling.

#### Scenario: A stream-delivered event is stored
- **WHEN** a sender delivers a CEF event over the stream transport
- **THEN** it is parsed and stored as a searchable external log

#### Scenario: Both framings are accepted
- **WHEN** senders deliver messages using octet-counted framing and newline-terminated framing
- **THEN** both are ingested

#### Scenario: An oversized message is refused and counted, never truncated
- **WHEN** a sender delivers a message longer than the configured bound
- **THEN** the message is refused and counted, and no partial event is stored

#### Scenario: A malformed message does not end the stream
- **WHEN** a sender delivers an unparseable message followed by a valid one
- **THEN** the unparseable message is counted, the valid one is stored, and the connection stays open

### Requirement: Evidentiary ingest authenticates the sender

The system SHALL offer external-log ingest over TLS with MUTUAL authentication, refusing at the handshake
any sender that does not present a certificate issued by the operator's authority.

Without it, anything able to reach the port can inject events into a store the product invites operators
to treat as evidence — and fabricated evidence is a worse failure than lost evidence. Transport
encryption alone does not address this: it protects a message in flight while leaving the sender
anonymous.

#### Scenario: A sender with an operator-issued certificate is accepted
- **WHEN** a sender presents a certificate issued by the configured authority
- **THEN** the connection is accepted and its messages are ingested

#### Scenario: A sender without a certificate is refused at the handshake
- **WHEN** a sender connects presenting no client certificate
- **THEN** the handshake fails and no message from it is stored

#### Scenario: A sender with an untrusted certificate is refused
- **WHEN** a sender presents a well-formed certificate from an authority the deployment does not trust
- **THEN** the handshake fails and no message from it is stored
