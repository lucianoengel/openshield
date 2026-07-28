# exact-data-matching Specification

## Purpose
Exact Data Matching (EDM, DLP-3): detect a flow carrying an ACTUAL value from the operator's
fingerprinted sensitive dataset — a specific customer record, not merely its format. The index is a
k-anonymized bloom filter (hashes only, never raw values), so it ships into the sandboxed classify
worker without the sensitive dataset leaving the operator (ADR-9, D10/D11). This first increment
matches single values with a bounded, measured false-positive rate and skips low-entropy tokens;
multi-cell record correlation, IDM, OCR, and index signing are follow-ups.

## Requirements

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

### Requirement: A configured record index reaches the running worker

The endpoint SHALL load a configured record index — verifying the operator signature when an index public
key is configured — and add its detector to the classifier that runs inside the sandboxed worker, so the
record semantics apply to files the deployed engine actually observes. A configured-but-unloadable index
SHALL abort the worker rather than leave it classifying without the detector the operator configured.

#### Scenario: A record's cells co-occurring in an observed file raise a decision
- **WHEN** a signed record index is configured and an observed file contains the threshold number of distinct cells of one indexed record
- **THEN** the pipeline records an exact-data decision for that file

#### Scenario: Cells of different records in an observed file raise nothing
- **WHEN** an observed file contains one cell each from two different indexed records
- **THEN** no exact-data decision is recorded

### Requirement: The shipped index builder MUST apply the distinctiveness filter and report what it skipped

The command-line index builder MUST apply the same distinctiveness filter the library defines, MUST
report how many values it skipped, and MUST refuse to write an index in which no value was
distinctive enough to index.

Indexing non-distinctive values does not weaken detection — it manufactures false positives, and a
false positive in an enforcing deployment blocks legitimate traffic from a control behaving exactly as
configured. An index over zero values is the inverse failure: the detector reports itself configured
and can never fire.

#### Scenario: Low-entropy values are skipped by the shipped builder

- **WHEN** an operator builds an EDM index from a file mixing distinctive identifiers with short or
  common words
- **THEN** the resulting index MUST match the distinctive values and MUST NOT match the low-entropy
  ones

#### Scenario: The skipped count is reported

- **WHEN** the builder skips any value
- **THEN** it MUST report how many were skipped

#### Scenario: An index with nothing distinctive is refused

- **WHEN** no value in the input is distinctive enough to index
- **THEN** the builder MUST fail rather than write an index that can never match
<!-- synced from edm-builder-distinctiveness -->
