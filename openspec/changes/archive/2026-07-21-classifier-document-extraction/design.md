## Context

The worker bounds the RAW input (8 MiB) before the classifier sees it. Extraction expands
that, so it needs its own bounds. OOXML is a ZIP of XML — stdlib archive/zip + tag
stripping extract the text with no external dependency.

## Goals / Non-Goals

**Goals:** detect PII/secrets inside DOCX/XLSX/PPTX, bounded against decompression bombs,
with a safe raw-scan fallback.

**Non-Goals:** PDF (a parser-dependency decision); legacy binary Office; OCR; recursion.

## Decisions

**Extract in the classifier, before the detectors.** One place, in the sandboxed worker.
`Classify` reads the (worker-bounded) bytes, tries `extractOOXML`, and scans the extracted
text if it is a document, else the raw bytes. A mis-detection degrades to "scan as-is",
never "scan nothing".

**Bounded three ways against a bomb (D13).** A per-entry LimitReader, a total extract
budget (16 MiB), and an entry-count cap (4096). A 4 KB zip that declares gigabytes hits the
ceiling and stops. The per-entry bound is detection-observable (a CPF past it is not found);
the total/count bounds are exhaustion guards. The read bound is proven real by a test that
places a hit past the ceiling and asserts it is missed.

**Only named user-text members are read.** word/*.xml, xl/sharedStrings + worksheets,
ppt/slides — the members that carry user content. Media/rels/theme members are skipped
(no content, only budget), and because only these named members are opened, a nested
archive inside the document is never recursively expanded.

**No JSON/heavy parser.** XML markup is stripped with a regex, not a full XML parser — the
detection signal is the text between tags; a streaming XML decoder would add surface for no
detection gain.

## Risks / Trade-offs

- **A hit past the per-entry ceiling is missed.** By construction — the honest limit of
  bounded extraction, mirroring the prefilter's prefix bound. A huge document's tail is not
  scanned; the alternative (unbounded expansion) is the bomb.
- **Tag-stripping is lossy** (it drops structure, merges cells/runs). Fine for pattern
  detection; a semantic extractor is a later, heavier option.
