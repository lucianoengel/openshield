## Why

The classifier scanned raw bytes, so PII inside an Office document was invisible — a CPF in
a .docx is deflate-compressed noise to a byte-level detector. Phase D1 adds document-
structure extraction: unzip a recognized OOXML container (DOCX/XLSX/PPTX) and pull its
text so the SAME detectors see the real content. This is exactly the parser/RCE surface the
sandbox split (D29/D35) was built for — it runs in the seccomp worker, never the privileged
agent.

## What Changes

- `internal/classify/documents.go`: `extractOOXML(data)` — detects a ZIP (magic), reads
  the user-text members (word/*.xml, xl/sharedStrings.xml, xl/worksheets/*.xml,
  ppt/slides/*.xml), strips XML markup, returns the concatenated text; bounded against a
  decompression bomb (per-entry, total, and entry-count ceilings). `Classify` runs it
  before the detectors; a non-document (or corrupt one) falls back to a raw scan.

## Capabilities

### Modified Capabilities
- `pattern-classifier`: extracts text from Office documents before detection, bounded.

## Impact

- New `internal/classify/documents.go`; `Classify` gains a pre-extraction step.
- Proven with REAL archive/zip-built documents: a CPF inside a .docx and a token inside an
  .xlsx are detected (D96 detectors compose over D1 extraction); plain text still works
  (raw fallback); a non-OOXML zip falls back to a raw scan (a stored CPF is still found);
  a CPF PAST the per-entry ceiling is NOT extracted (the bound is real); a decompression
  bomb (a tiny zip declaring 64 MiB) terminates bounded, no OOM. Guards mutation-tested
  (entry-read-unbounded; text-entry-matcher-disabled).
- NOT in scope (stated): PDF (needs a real parser dependency — a separate decision);
  legacy binary Office (.doc/.xls); XML-entity decoding (digits/letters, the detection
  signal, are not entity-encoded); nested-archive recursion (only named OOXML text members
  are read, so an inner zip is not expanded). Runs in the sandboxed worker (D35); adds no
  parser to the privileged agent (D72 — classify gained only archive/zip).
