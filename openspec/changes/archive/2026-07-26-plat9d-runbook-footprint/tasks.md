## 1. Runbook
- [x] 1.1 `docs/runbook.md`: deployment footprint (what it is / is not), components, procedures
      (verify a release, emergency disable, verify a restore, schema skew, change configuration), and
      each procedure's honest limit stated where it is used.

## 2. Drift guard
- [x] 2.1 A `doccheck` test cross-checking documented components against `cmd/` in BOTH directions
      (**mutation:** check only one direction → a removed-but-documented binary passes → FAILS).

## 3. Gate and land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.2 Record D268; roadmap PLAT-9 residual updated.
- [x] 3.3 Sync specs and archive.
