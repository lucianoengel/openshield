# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier extracts text from PDF documents, bounded and panic-contained
The classifier MUST detect a PDF (by its magic) and extract its text before running
detectors, so content inside a PDF is classified rather than its compressed byte structure.
Extraction MUST be bounded by the extraction ceiling and MUST contain a parser panic — a
malformed or hostile PDF MUST fall back to scanning the raw bytes, never crash the
classifier. The PDF parser MUST run in the sandboxed worker and MUST NOT be linked into the
privileged agent.

#### Scenario: Compressed PDF text is extracted and a malformed PDF does not crash
- **WHEN** the classifier scans a PDF whose text is compressed, and separately a malformed PDF
- **THEN** the compressed content is parsed and detected (not found in the raw bytes), and the malformed PDF falls back to a raw scan without crashing
