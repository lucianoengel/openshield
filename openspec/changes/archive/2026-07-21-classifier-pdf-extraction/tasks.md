# Tasks — PDF text extraction (D99)

## 1. Extractor

- [x] 1.1 `internal/classify/pdf.go`: extractPDF (%PDF- magic → ledongthuc/pdf parse → GetPlainText, bounded by maxExtractBytes, recover-guarded); Classify tries it after OOXML. Pure Go, worker-only (D72 guard green).

## 2. Proof (real PDF; guard mutation-tested)

- [x] 2.1 **Test**: a CPF inside a FlateDecode-COMPRESSED PDF is detected (and asserted absent from the raw bytes, so extraction — not fallback — found it); a malformed PDF does not crash and falls back to a raw scan.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D99.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| PDF extraction disabled (always false) | the compressed-stream CPF becomes unreachable via raw scan → not detected |
| (PDF magic fast-path removed) | NOT behavior-observable — NewReader errors on non-PDF anyway; kept as optimization |
| (recover guard removed) | NOT triggered by the corpus — the library errored, never panicked, on every crafted input; kept as defense-in-depth for adversarial/fuzzer inputs |
