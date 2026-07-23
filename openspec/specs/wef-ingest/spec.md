# wef-ingest Specification

## Purpose
Parsing Windows Event Forwarding XML and persisting each event as a searchable external-log record
(SIEM-4), so Windows endpoint/DC security events are queryable beside CEF, CloudTrail, and agent
telemetry. A faithful decoder over the fixed Windows Event schema, reusing the external-log store and
the shared directory-ingest helper; Windows events are UNVERIFIED third-party records, stored apart
from verified agent telemetry.


### Requirement: Windows Event XML parsing

The system SHALL parse Windows Event Forwarding XML — a single `<Event>` or an `<Events>` batch — into
structured records carrying the documented fields (event id, provider, level, time, computer, channel,
and the EventData name/value pairs). Malformed XML SHALL be an error; a record with no event id SHALL be
counted as skipped, never emitted as a partial record.

#### Scenario: A Windows security event is parsed
- **WHEN** a WEF document with a logon (EventID 4624) event is parsed
- **THEN** the record's event id, provider, computer, time, and EventData fields are returned

#### Scenario: A batch of events is parsed
- **WHEN** an `<Events>` document containing several `<Event>` elements is parsed
- **THEN** each event is returned as a record

#### Scenario: Malformed XML is rejected
- **WHEN** a body that is not well-formed XML is parsed
- **THEN** parsing returns an error and no records

### Requirement: WEF events are persisted and searchable

The system SHALL persist each parsed WEF event as an external-log record (vendor "microsoft", product
"windows") in the shared external-log store, searchable by the same `/logs` query as CEF and CloudTrail.
Windows events SHALL be stored alongside — not confused with — verified agent telemetry.

#### Scenario: A parsed Windows event is stored and found
- **WHEN** a WEF file is ingested
- **THEN** a search for vendor "microsoft" returns its events with event id and computer intact

### Requirement: Idempotent WEF directory ingest

The system SHALL ingest WEF files dropped into a directory, persist their records, and mark each
processed file so a restart does not re-ingest it. A file that fails to read, parse, or persist SHALL be
marked failed and counted, never re-tried indefinitely and never left to block the directory. Only the
elected leader SHALL ingest.

#### Scenario: A dropped WEF file is ingested once
- **WHEN** a WEF file is dropped into the watched directory and the poller runs
- **THEN** its events are persisted and the file is marked ingested
- **AND** running the poller again does not persist the events a second time

#### Scenario: A poison WEF file does not block ingest
- **WHEN** a malformed file is dropped into the watched directory
- **THEN** it is marked failed and counted, and subsequent valid files still ingest

> Field-level hunting: this source's parsed fields are stored in `external_logs.fields` (JSONB) and
> searchable via the shared field filter — see `cef-syslog-ingest` (SIEM field-level hunting, D212).
