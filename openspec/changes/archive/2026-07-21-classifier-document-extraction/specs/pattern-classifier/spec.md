# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier extracts text from Office documents before detection, bounded
The classifier MUST detect an Office Open XML container (DOCX/XLSX/PPTX) and extract the
text of its user-content members before running detectors, so content inside a document is
classified rather than its compressed bytes. Extraction MUST be bounded against a
decompression bomb — a per-member read limit, a total extraction ceiling, and an entry-count
cap — so a small archive declaring a huge expansion cannot exhaust memory. A non-document,
a corrupt archive, or an archive with no recognized text members MUST fall back to scanning
the raw bytes, never to scanning nothing.

#### Scenario: PII inside a document is detected and a bomb is bounded
- **WHEN** the classifier scans a DOCX/XLSX containing sensitive content
- **THEN** the content is extracted and detected; a non-document falls back to a raw scan; and a decompression bomb is bounded rather than exhausting memory
