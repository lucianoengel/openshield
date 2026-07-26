## 1. Detection
- [x] 1.1 `SchemaSkew(ctx, pool) (embedded, applied int, err error)` in `internal/store/postgres`.
- [x] 1.2 The server reports skew at boot, loudly, naming the forward-only asymmetry; startup proceeds.
- [x] 1.3 Expose `openshield_schema_skew` on `/metrics`.

## 2. Tests
- [x] 2.1 Level → no skew; a database with MORE applied migrations → skew reported with the count
      (**mutation:** keep `applied >= want` semantics and report nothing → FAILS).
- [x] 2.2 Startup is not prevented by skew (**mutation:** refuse to start → FAILS).

## 3. Gate and land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.2 Record D267; roadmap PLAT-9 residuals updated.
- [x] 3.3 Sync specs and archive.
