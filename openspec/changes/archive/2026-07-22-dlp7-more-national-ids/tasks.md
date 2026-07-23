## 1. Proto + detectors

- [x] 1.1 `DETECTOR_TYPE_AADHAAR = 22`, `DETECTOR_TYPE_UK_NINO = 23`; `make proto`.
- [x] 1.2 `verhoeffValid(string) bool` + `aadhaar` detector (candidate regex + first-digit 2-9 + Verhoeff).
- [x] 1.3 `ukNINO` detector reusing `contextNear` (format + prefix rules + NI keyword).
- [x] 1.4 Register both in `New()`.

## 2. Tests (mutation-verified)

- [x] 2.1 A Verhoeff-valid Aadhaar (spaced + bare) → hit; a checksum-tampered one → no count.
- [x] 2.2 A NINO near "national insurance" → hit; a bare NINO with no keyword → no count.
- [x] 2.3 Mutations: `verhoeffValid` always-true → the tampered-Aadhaar test FAILs; NINO without contextNear (bare structural) → the no-context test FAILs.

## 3. Gate + close

- [x] 3.1 `make proto-check`; `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 3.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 3.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
