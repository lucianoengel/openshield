# cef-syslog-ingest Specification

## Purpose
Receiving CEF-over-syslog from the estate, persisting each parsed event as a searchable external-log
record (SIEM-4), so OpenShield ingests third-party security logs — not only its own signed telemetry.
The CEF parser (D202) and the hardened syslog listener are composed with a persisting sink; external
logs are UNVERIFIED third-party events, stored apart from attributable signed telemetry.


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
