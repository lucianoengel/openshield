## 1. Validate the limit param
- [x] 1.1 `/incidents` (correlate.go): replace `queryInt(r, "limit", 100)` with `intParam(q, "limit", 100)` + a 400 on error (reuse the `q` already built in the handler).
- [x] 1.2 `/alerts` (operator_read.go): replace `queryInt(r, "limit", 100)` with `intParam(r.URL.Query(), "limit", 100)` + a 400 on error.
- [x] 1.3 Remove the now-unused `queryInt` helper.

## 2. Tests (mutation-verified)
- [x] 2.1 `/incidents?limit=abc` and `?limit=-5` → 400; `?limit=5` → 200; no `limit` → 200 (default). Real handler over Postgres.
- [x] 2.2 `/alerts?limit=abc` → 400; valid/absent → 200.
- [x] 2.3 Mutation: reverting a handler to `queryInt` (silent default) → the malformed-limit 400 test FAILs.

## 3. Gate + close
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; restore binaries.
- [x] 3.2 decisions.md (D219); sync control-plane spec; doccheck.
- [x] 3.3 Archive; commit; push; roadmap.
