## 1. Command
- [x] 1.1 `openshieldctl restore-verify`: witness key MANDATORY; require Consistent AND anchored
      completeness; report entries beyond AnchoredThrough; three distinct exit codes.
- [x] 1.2 Reuse the existing VerifyChain/anchor path — no second implementation of verification.

## 2. Tests
- [x] 2.1 No witness key → NOT verified (**mutation:** fall back to `verify`'s degraded mode → FAILS).
- [x] 2.2 Consistent but unanchored → NOT verified (**mutation:** accept CompletenessUnverified → FAILS).
- [x] 2.3 Consistent and anchored → verified; the unproven tail is reported.
- [x] 2.4 The three outcomes map to three distinct exit codes.

## 3. Gate and land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.2 Record D266; roadmap PLAT-9 → verified restore done, the rest named.
- [x] 3.3 Sync specs and archive.
