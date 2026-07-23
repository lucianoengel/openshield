## ADDED Requirements

### Requirement: CloudTrail delivery parsing

The system SHALL parse an AWS CloudTrail JSON delivery (`{"Records":[ … ]}`) into structured records
carrying the documented fields (event time, event source, event name, region, source IP, actor
identity, error code, account). A body that is not JSON or has no `Records` array SHALL be an error; a
single record missing required identity SHALL be counted as skipped, never emitted as a partial record.

#### Scenario: A CloudTrail delivery is parsed
- **WHEN** a valid CloudTrail delivery with a `ConsoleLogin` record is parsed
- **THEN** the record's event name, source, region, source IP, and actor identity are returned

#### Scenario: A non-CloudTrail body is rejected
- **WHEN** a body that is not JSON, or JSON without a `Records` array, is parsed
- **THEN** parsing returns an error and no records

### Requirement: CloudTrail events are persisted and searchable

The system SHALL persist each parsed CloudTrail record as an external-log record (vendor "aws", product
"cloudtrail") in the shared external-log store, searchable by the same filtered search as other external
logs. Cloud events SHALL be stored alongside — not confused with — verified agent telemetry.

#### Scenario: A parsed event is stored and found
- **WHEN** a CloudTrail delivery is ingested
- **THEN** a search for vendor "aws" returns its events with event name and source IP intact

### Requirement: Idempotent directory ingest

The system SHALL ingest CloudTrail deliveries dropped into a directory, persist their records, and mark
each processed file so a restart does not re-ingest it. A file that fails to read, parse, or persist
SHALL be marked failed and counted, never re-tried indefinitely and never left to block the directory.
Only the elected leader SHALL ingest, so a multi-instance deployment does not double-store.

#### Scenario: A dropped file is ingested once
- **WHEN** a CloudTrail file is dropped into the watched directory and the poller runs
- **THEN** its records are persisted and the file is marked ingested
- **AND** running the poller again does not persist the records a second time

#### Scenario: A poison file does not block ingest
- **WHEN** a malformed file is dropped into the watched directory
- **THEN** it is marked failed and counted, and subsequent valid files still ingest
