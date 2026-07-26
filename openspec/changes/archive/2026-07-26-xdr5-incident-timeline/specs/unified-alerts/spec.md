## ADDED Requirements

### Requirement: A unified alert carries a reference to what produced it

A unified alert projected from a decision SHALL record the originating event id and decision id as
first-class columns, so a consumer can reach the evidence behind the alert without parsing the dedup key.
An alert with no originating decision — a server-side derivation such as peer-UEBA — SHALL leave both
references empty, and consumers SHALL treat that emptiness as the meaningful statement "there is no
originating endpoint event", not as missing data.

#### Scenario: A projected alert records its origin
- **WHEN** a verified decision is projected into the unified stream
- **THEN** the stored alert carries that decision's id and its originating event's id

#### Scenario: A server-derived alert records no origin
- **WHEN** the server-side peer-UEBA detector records a unified alert
- **THEN** the stored alert's event and decision references are empty, and nothing infers one
