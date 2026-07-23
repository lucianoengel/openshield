## ADDED Requirements

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
