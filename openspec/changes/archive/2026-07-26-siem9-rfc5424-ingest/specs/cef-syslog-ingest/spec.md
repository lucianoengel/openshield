## ADDED Requirements

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
