## 1. The fix

- [x] 1.1 `DenyEvaluator` gains the monitored-directory scope; the default-deny applies only to a
      resolved path under one of them.
- [x] 1.2 `cmd/openshield-agent` passes `OPENSHIELD_EXEC_MONITOR_DIRS` into the evaluator.
- [x] 1.3 The startup warning names the directories the default-deny covers.

## 2. Prove it

- [x] 2.1 Unit: allowlisted-in-scope allows; unlisted-in-scope blocks; anything out of scope allows;
      a deny-listed binary out of scope still blocks.
- [x] 2.2 Mutation: drop the scope check -> the out-of-scope case blocks -> FAILS.
- [x] 2.3 The VM scenario is extended to execute a SYSTEM binary while whitelisting is active — the
      case that bricked the machine.
- [x] 2.4 Run it on the rooted VM and paste the result.

## 3. Land

- [x] 3.1 `make quick`, then the package tests.
- [x] 3.2 Record the finding in `docs/unwired-audit.md`.
- [x] 3.3 Commit with a D-number, archive WITH the spec sync, check CI.
