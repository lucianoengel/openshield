# execaudit-connector

## ADDED Requirements

### Requirement: The exec source MUST continue reading a file that grows

When the configured exec-audit source is a regular file, the connector MUST ingest records appended
after it started reading, and MUST recover when the file is truncated in place or replaced by
rotation.

A source that drains the file once and stops is a detector that reports itself enabled and then sees
nothing: every execution before startup is ingested and none after it, with no signal that this has
happened.

#### Scenario: A record appended after startup is ingested

- **WHEN** an exec record is appended to the source file after the engine has begun reading it
- **THEN** the execution MUST enter the pipeline and produce an audit entry

#### Scenario: The source is resumed after truncation

- **WHEN** the source file is truncated and new records are written
- **THEN** the new records MUST be ingested

### Requirement: The exec source ending MUST be reported

If the exec source ends while the engine is still running, the engine MUST report it, stating that no
further executions will be observed.

A shutdown is not a report-worthy event; a source that ends underneath a running engine is a loss of
endpoint process visibility, and the operator cannot tell it from a quiet estate.

#### Scenario: An ended source is announced

- **WHEN** the exec source reaches a definitive end while the engine continues to run
- **THEN** the engine MUST log that the exec source ended and that further executions will not be seen
