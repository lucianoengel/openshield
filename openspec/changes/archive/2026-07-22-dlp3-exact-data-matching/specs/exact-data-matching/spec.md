## ADDED Requirements

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
