## Why

D97 extracted text from OOXML documents; PDF — the other dominant document format — was
still opaque to detection (its text is compressed inside content streams). Phase D1's PDF
half adds pure-Go PDF text extraction so PII/secrets inside a .pdf are seen by the same
detectors. This is the RCE surface the sandbox split (D29/D35) exists for; the parser runs
in the seccomp worker, never the privileged agent (D72).

## What Changes

- `internal/classify/pdf.go`: `extractPDF(data)` — detects the `%PDF-` magic, parses via
  `github.com/ledongthuc/pdf` (pure Go, no cgo), extracts plain text bounded by the
  existing extract ceiling. Guarded by `recover` — a parser panic on hostile input
  degrades to a raw scan, never crashes the classifier. `Classify` tries it after OOXML.
- New dependency: `github.com/ledongthuc/pdf` (MIT, pure Go).

## Capabilities

### Modified Capabilities
- `pattern-classifier`: extracts text from PDF documents before detection, bounded and
  panic-contained.

## Impact

- New `internal/classify/pdf.go`; `go.mod` gains a pure-Go PDF dependency; `Classify` tries
  PDF after OOXML.
- Proven with a REAL PDF built in-test whose content stream is FlateDecode-COMPRESSED — so
  a detected CPF can ONLY come from real parsing + decompression, not the raw-scan fallback
  (the test asserts the CPF is absent from the raw bytes); a malformed PDF does not crash
  and falls back to a raw scan. Guard mutation-tested (extraction-disabled → the compressed
  CPF becomes unreachable).
- NOT in scope (stated): encrypted PDFs (the library supports a password callback — a
  credential-handling decision); scanned/image PDFs (needs OCR); the `%PDF-` magic fast-path
  and the `recover` guard are defense-in-depth not triggered by the current test corpus
  (the parser errored rather than panicked on every crafted malformed input — recover
  remains correct for adversarial inputs a fuzzer would find). Pure Go (no cgo), runs in the
  sandboxed worker (D35), does not reach the privileged agent (D72, guard green).
