## ADDED Requirements

### Requirement: Alerts are recorded keyed to the entity graph

The system SHALL record a normalized alert keyed by the XDR entity — resolving the alert's subject to an
entity via the entity graph, so an alert binds to the SAME entity the device/user model knows. An alert
whose subject cannot be resolved to an entity SHALL NOT be recorded as an unkeyed row; the failure SHALL
be counted, and it SHALL NOT break the producer's own (authoritative) recording.

#### Scenario: An alert binds to the device entity
- **WHEN** a server-side detector records a unified alert for a device subject the graph knows
- **THEN** the unified alert's entity id equals the entity the device graph resolved for that subject

#### Scenario: A graph failure does not break the producer
- **WHEN** the entity resolution for a unified alert fails
- **THEN** the failure is counted and the producer's own alert record is still written

### Requirement: A cross-domain per-entity alert view

The system SHALL return all alerts for one entity across domains, newest first — the input a cross-domain
correlation engine reads. Alerts from different domains for the same entity SHALL group under that one
entity.

#### Scenario: Two domains' alerts share one entity
- **WHEN** two alerts from different domains are recorded for the same subject
- **THEN** both resolve to one entity id and a per-entity query returns both

### Requirement: Unified alerts deduplicate by key

The system SHALL deduplicate unified alerts by a detector-namespaced key, so a re-detection of the same
logical alert is one row (not multiplied correlation input).

#### Scenario: A re-detected alert is one row
- **WHEN** the same logical alert (same dedup key) is recorded twice
- **THEN** exactly one unified-alert row exists for it
