## 1. Aggregation

- [x] 1.1 `EntityRisk(ctx, window, now)` — per entity, the MAX of (severity floor × recency weight) over its
  unified alerts in the window, returning entity id → score.
- [x] 1.2 Tests: a high-severity alert produces a high score; an OLD alert scores lower than a recent one of
  the same severity (**mutation:** drop the recency weight → FAILS); max-not-sum (many low alerts do not
  outrank one critical).

## 2. Publication to every alias

- [x] 2.1 `PublishEntityRisk` enumerates the entity's aliases and publishes the score for each, signed like
  any risk update.
- [x] 2.2 Test: a linked device⋈user entity publishes to BOTH aliases (**mutation:** publish only the
  first alias → FAILS).

## 3. Never lower

- [x] 3.1 `RiskStore.Set` raises but does not lower. Test: a lower published risk does not overwrite a
  higher held one (**mutation:** plain overwrite → FAILS).

## 4. Wire and land

- [x] 4.1 Drive it from the SOAR-2 scheduled loop (leader-only).
- [x] 4.2 End-to-end over REAL pub/sub: a high-severity HIPS alert on device A raises the risk a gateway
  RiskStore holds for A.
- [x] 4.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; roadmap + register; commit `XDR-7`, sync, archive.
