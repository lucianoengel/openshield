# Tasks — HIPS process enforcers (D111)

## 1. Enforcers

- [x] 1.1 `internal/enforcers/process`: KillEnforcer (KILL_PROCESS, pid target, fail-safe pid≤1/self/non-numeric) + DenyEnforcer (DENY_EXEC via ExecController seam, nil-controller/empty-target error); per-OS platformKill; both implement the existing TargetedEnforcer.

## 2. Proof (real process; guards mutation-tested)

- [x] 2.1 **Test**: KILL_PROCESS kills a real spawned sleep (SIGKILLed not clean-exit); refuses pid≤1/self/non-numeric/empty; DENY_EXEC records the deny, errors on nil-controller/empty-target.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D111.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| pid≤1 (kernel/init) guard removed | the "1"/"0" refusal fails (literally killed the test runner) |
| self-pid guard removed | the self-pid refusal fails (killed the test runner) |
| deny nil-controller guard removed | a deny with no controller no longer errors |
