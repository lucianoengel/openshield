# exact-data-matching

## ADDED Requirements

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
