## ADDED Requirements

### Requirement: Retention purges are recorded as compliance events

The system SHALL record each retention purge it runs — the target purged, the number of rows removed,
the cutoff (retention boundary) applied, the policy that drove it, and when it ran — as a durable,
queryable compliance event. A recording failure SHALL be counted and SHALL NOT block or undo the purge.

#### Scenario: A purge is recorded
- **WHEN** the retention loop purges a target
- **THEN** a retention event records the target, row count, cutoff, policy, and time

#### Scenario: A zero-row purge is still recorded
- **WHEN** a scheduled purge runs but removes no rows
- **THEN** a retention event is still recorded (proving retention executed on schedule)

### Requirement: A queryable compliance report

The system SHALL expose a time-windowed, filtered query over the recorded retention events, so a
compliance auditor can see what was purged, when, and under which policy. A malformed filter SHALL be
rejected, not silently ignored.

#### Scenario: The report returns recorded purges
- **WHEN** retention events exist and a report is queried for a time window
- **THEN** the matching events are returned, newest first

#### Scenario: A malformed filter is rejected
- **WHEN** the report is queried with a malformed since/until/limit
- **THEN** the request is a 400, not an over-broad result
