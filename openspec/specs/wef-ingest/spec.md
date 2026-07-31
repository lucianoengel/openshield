# wef-ingest Specification

## Purpose
Parsing Windows Event Forwarding XML and persisting each event as a searchable external-log record
(SIEM-4), so Windows endpoint/DC security events are queryable beside CEF, CloudTrail, and agent
telemetry. A faithful decoder over the fixed Windows Event schema, reusing the external-log store and
the shared directory-ingest helper; Windows events are UNVERIFIED third-party records, stored apart
from verified agent telemetry.

## Requirements

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

### Requirement: Sysmon events arrive named by their action, not by their number

A Windows event from the Sysmon provider SHALL be stored with an action name rather than a provider/ID
string, under a product that distinguishes endpoint telemetry from the Security channel, and its own
field names SHALL be reachable through the canonical cross-vendor vocabulary.

Sysmon events already arrived: they are Windows events, so the existing connector parsed them and stored
their EventData. What arrived was unusable at the point it mattered. `Microsoft-Windows-Sysmon/1` is the
single most important endpoint telemetry line Windows produces — a process was created — and stored as
the string "1" it is huntable only by an analyst who has memorised Microsoft's table. In practice that
means by nobody, and the richest Windows source in the estate sits in the store being counted.

The naming layer SHALL INTERPRET NOTHING. Which process creation is suspicious is the policy's and the
detector's job, exactly as for every other source; a connector that decided what was bad would put
detection logic where nobody looks for it.

It SHALL NEVER FILTER. Sysmon's schema grows between releases, so a field the map does not know SHALL
still be stored under its own name and remain huntable — a mapping layer that dropped what it did not
recognise would silently narrow the estate's best endpoint source with every Microsoft release.

An UNMAPPED event ID SHALL keep its identifying string rather than being given a placeholder name.
Mapping every unknown ID to one label collapses each new event type into a single bucket, from which a
hunt returns an unrelated mixture and nobody notices the map has fallen behind.

The provider SHALL be matched by prefix. Deployments see it bare, suffixed, and alongside a GUID, and an
exact comparison would treat those as ordinary Windows events — not a crash, but a whole endpoint fleet
quietly losing its naming.

Where Sysmon carries both a process and its parent, the canonical process field SHALL resolve to the
process the event is ABOUT. Resolving to the parent attributes every process creation on the host to the
shell that started it — a confidently wrong answer rather than a missing one, and invisible in a search
result because the query matches either way.

#### Scenario: A Sysmon event is stored under its action
- **WHEN** a Sysmon process-create and DNS-query event are ingested
- **THEN** they are stored as `process_create` and `dns_query` under the sysmon product

#### Scenario: An unmapped event ID is not given a name
- **WHEN** an event ID outside the mapped set is seen
- **THEN** it keeps its identifying string

#### Scenario: Sysmon fields answer the shared hunt
- **WHEN** a canonical hunt is run for a user, a process or a domain
- **THEN** the Sysmon record is returned, and its projected process is the created process rather than
  its parent
