# Tasks — document-structure extraction (D97)

## 1. Extractor

- [x] 1.1 `internal/classify/documents.go`: extractOOXML (zip magic → read named OOXML text members → strip XML → concatenated text), bounded (per-entry LimitReader, 16 MiB total, 4096 entries); Classify runs it pre-detection with a raw-scan fallback.

## 2. Proof (real zips; guards mutation-tested)

- [x] 2.1 **Test**: CPF in a .docx and token in an .xlsx detected; plain text still works; non-OOXML zip falls back to raw scan; a CPF past the per-entry ceiling is NOT extracted (bound real); a decompression bomb terminates bounded.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D97.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| per-entry read LimitReader removed (unbounded) | a CPF past the per-entry ceiling is then found |
| ooxml text-entry matcher disabled | DOCX/XLSX content no longer detected |
| (zip-magic prefix check removed) | NOT behavior-observable — zip.NewReader errors on non-zip anyway; kept as a fast-path optimization, noted honestly |
