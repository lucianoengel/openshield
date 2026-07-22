# document-fingerprinting Specification

## Purpose
Indexed Document Matching (IDM, DLP-3): fingerprint a sensitive DOCUMENT by the hashes of its
overlapping word k-gram shingles and detect content that contains a substantial portion of it — an
excerpt or a reformat — so pasting a paragraph of a confidential document or uploading a copied source
file is caught. The index stores only shingle hashes (k-anonymized), so it ships into the sandboxed
worker without the document leaving the operator. A match fires on a threshold FRACTION of a document's
shingles; winnowing (for very large corpora) and OCR are follow-ups.


### Requirement: Document fingerprint index

The system SHALL fingerprint a sensitive document as the set of hashes of its overlapping word k-gram
shingles, storing only hashes (no raw text), so the index can be shipped into the sandboxed worker
without the document leaving the operator. Reloading a serialized index MUST NOT expose any raw document
text, and a document too small to produce a meaningful shingle set MUST be skipped and counted.

#### Scenario: The serialized document index carries no raw text

- **WHEN** a document index is built and serialized
- **THEN** the serialized bytes contain none of the document's raw text, and reloading matches the same
  documents

### Requirement: Document match detection with excerpt and reformat tolerance

The system SHALL detect content that contains a substantial portion of a fingerprinted document — firing
when the content contains at least a threshold fraction of that document's shingles — and report it as a
document match distinct from a structured-data match. Reformatting (whitespace, punctuation, casing) and
excerpting MUST NOT prevent a match, and unrelated content MUST NOT match.

#### Scenario: An excerpt of a fingerprinted document matches

- **WHEN** content contains a reformatted excerpt covering at least the threshold fraction of a
  fingerprinted document's shingles
- **THEN** the detector reports a document match

#### Scenario: A small snippet below the fraction does not match

- **WHEN** content contains only a few shingles of a document, below the threshold fraction
- **THEN** the detector does not report a match for that document

#### Scenario: Unrelated content does not match

- **WHEN** content shares no shingles with any fingerprinted document
- **THEN** the detector reports no document match
