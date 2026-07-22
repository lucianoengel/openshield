# exact-data-matching Specification

## Purpose
Exact Data Matching (EDM, DLP-3): detect a flow carrying an ACTUAL value from the operator's
fingerprinted sensitive dataset — a specific customer record, not merely its format. The index is a
k-anonymized bloom filter (hashes only, never raw values), so it ships into the sandboxed classify
worker without the sensitive dataset leaving the operator (ADR-9, D10/D11). This first increment
matches single values with a bounded, measured false-positive rate and skips low-entropy tokens;
multi-cell record correlation, IDM, OCR, and index signing are follow-ups.


### Requirement: Exact-data-match index is k-anonymized

The system SHALL build a fingerprint index of an operator's sensitive values as a bloom filter that
stores only hashes — never the raw values — with a bounded, computable false-positive rate, so the index
can be shipped into the sandboxed worker without the sensitive dataset leaving the operator. Serializing
and reloading the index MUST NOT expose any raw value, and the index builder MUST skip low-entropy tokens
that would over-match.

#### Scenario: The serialized index carries no raw value

- **WHEN** an index is built from sensitive values and serialized
- **THEN** the serialized bytes contain none of the raw values, and reloading yields an index that
  matches the same values

#### Scenario: Low-entropy tokens are not indexed

- **WHEN** a dataset contains short/common tokens alongside distinctive values
- **THEN** the builder indexes the distinctive values and skips the low-entropy ones

### Requirement: Exact-data-match detection

The system SHALL detect when content contains a value present in the EDM index — matching a specific
sensitive value regardless of its formatting — and report it as an exact-data-match detection distinct
from a format detection. A value not in the index MUST NOT be reported except at the index's bounded
false-positive rate.

#### Scenario: An indexed value in content is detected

- **WHEN** content contains a value that was indexed (in any equivalent formatting)
- **THEN** the EDM detector reports an exact-data match

#### Scenario: A distinctive non-indexed value is not detected

- **WHEN** content contains a distinctive value that was not indexed
- **THEN** the EDM detector does not report it (within the index's bounded false-positive rate)


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
