## ADDED Requirements

### Requirement: Record-level (multi-cell) exact-data matching

The system SHALL support record-level exact-data matching: a match fires only when a threshold number of
distinct cells of the SAME fingerprinted record co-occur in the content, so a single coincidental field
does not trigger and precision is far higher than single-value matching. The record index MUST store only
cell fingerprints (no raw values), and MUST skip records with fewer distinctive cells than the threshold
(reporting the skipped count).

#### Scenario: A record matches when enough of its cells co-occur

- **WHEN** content contains at least the threshold number of distinct cells of one fingerprinted record
- **THEN** the detector reports an exact-data (record) match

#### Scenario: A single matching cell does not fire

- **WHEN** content contains only one cell of a record (below the threshold)
- **THEN** the detector does not report a match for that record

#### Scenario: Cells from different records do not combine

- **WHEN** content contains one cell each from two different records (neither reaching the threshold alone)
- **THEN** the detector reports no record match

#### Scenario: The record index carries no raw value

- **WHEN** a record index is built and serialized
- **THEN** the serialized bytes contain none of the raw cell values, and reloading matches the same records
