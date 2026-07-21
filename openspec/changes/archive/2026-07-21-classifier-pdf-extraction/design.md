## Context

OOXML extraction (D97) proved the pattern: detect the container, extract text, scan it,
fall back to raw. PDF is the same shape with a different parser — but PDF parsing is the
canonical crash/DoS surface, so it needs a panic guard on top of the sandbox.

## Goals / Non-Goals

**Goals:** extract PDF text so detectors see it; contain a hostile PDF (bounded + panic
recovery); pure Go (runs in the seccomp worker).

**Non-Goals:** encrypted PDFs; OCR of scanned PDFs; layout fidelity.

## Decisions

**Pure-Go library, in the sandboxed worker.** `github.com/ledongthuc/pdf` is pure Go (no
cgo), so it runs behind the worker's seccomp filter — the whole reason the parser surface
was split off (D29/D35). It does not reach the privileged agent (D72; the deps guard stays
green because classify is worker-only).

**recover() around the parse.** A PDF parser on hostile input is exactly the ClamAV-CVE
class of bug the sandbox was built for; defense in depth wraps the parse in a recover so a
panic degrades to a raw scan rather than crashing the classifier. Honesty: no crafted
malformed input in the test corpus actually panicked this library (it errored cleanly), so
the recover is not test-triggered — it is kept for the adversarial inputs a fuzzer would
find, alongside the bounded read.

**The test compresses the stream — proving extraction, not the fallback.** The in-test PDF
FlateDecode-compresses its content stream, so the CPF is NOT in the raw bytes (the test
asserts this). A detection therefore can only come from real parsing + decompression — the
mistake caught during development, where an uncompressed stream let the raw-scan fallback
find the CPF and the extraction path went untested.

## Risks / Trade-offs

- **A third-party parser is new attack surface.** Mitigated by pure-Go + seccomp + recover
  + bounded read; the alternative (no PDF detection) leaves the most common exfil document
  format blind.
- **Encrypted/scanned PDFs are missed.** Explicit non-goals; a miss, not a false positive.
