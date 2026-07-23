## 1. Recursive extraction

- [x] 1.1 `maxArchiveDepth` const; `extractContent(data, depth, *budget)` — OOXML → PDF → general-zip → raw, recursing members through itself, sharing the budget.
- [x] 1.2 `extractZipArchive(data, depth, *budget)` — extract EVERY member (not just OOXML), recurse containers, bounded by shared budget / entry cap / depth; best-effort per member.
- [x] 1.3 `Classify` calls `extractContent(text, 0, &budget)` (budget = maxExtractBytes) in place of the single-level OOXML/PDF check.

## 2. Tests (mutation-verified)

- [x] 2.1 A valid card number in a plain-text file inside a ZIP → the credit-card detector hits (previously missed).
- [x] 2.2 The same file DOUBLE-zipped → still hits (recursion).
- [x] 2.3 A `.docx` inside a `.zip` → its OOXML text is extracted (member OOXML branch).
- [x] 2.4 Plain text (non-archive) → detection unchanged; a corrupt/huge archive is bounded (no hang/OOM).
- [x] 2.5 Mutations: `extractZipArchive` returns raw without extracting members → the in-zip test FAILs; the depth cap set to 0 (no recursion) → the double-zip test FAILs.

## 3. Gate + close

- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 3.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 3.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
