## 1. The import-direction check

- [x] 1.1 `scripts/check-capability-boundary.sh`: `go list -deps ./internal/core` must contain
      none of `internal/connectors|enforcers|classify|policy|store`. Fails the build; mirrors
      `check-core-deps.sh` in style
- [x] 1.2 Wire it into the `invariants` CI job next to the other boundary checks

## 2. The fitness test

- [x] 2.1 `internal/fitness` package, `fitness_test`. Define `testConnector` (Event producer),
      `testStage`, `testEnforcer` locally; wire via `core.Registry`/`core.Dispatcher`/`Enforcer`
- [x] 2.2 **Test**: dispatch an Event through the out-of-tree stage to a Decision the test enforcer
      advertises and enforces. `TestCapabilityAddedFromOutsideCore`
- [x] 2.3 The test package imports ONLY `internal/core` + `internal/core/corev1` — no concrete
      capability package. A comment states this is the proof

## 3. The honesty guards

- [x] 3.1 Package doc quoting D26: green is necessary, not sufficient; the test is gameable; the
      real test is a new-shape capability (T-004)
- [x] 3.2 **Test**: the D26/T-004 "necessary but not sufficient" caveat is present in the docs, so
      it cannot be dropped while the green check remains. `TestFitnessTestKnowsItsLimits`
- [x] 3.3 **Test**: the capability-boundary script exists and passes, so removing it fails CI.
      `TestCapabilityBoundaryCheckExists`
- [x] 3.4 Reference the existing isolation guards (`TestStageInterfaceExposesNoSiblingAccess`,
      `enforcerisolation`) by name as the guards for the known gaming vectors

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` under D26 that the CI fitness test and boundary check are
      now built, and remain necessary-not-sufficient
- [x] 4.2 Mark T-014 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| core imports a capability package (`internal/classify`) | `scripts/check-capability-boundary.sh` exits 1; `TestCapabilityBoundaryCheckExists` fails |
| the D26 "necessary but not sufficient" caveat deleted from docs | `TestFitnessTestKnowsItsLimits` |

The fitness test imports only `internal/core` + `corev1` — a reviewer who sees a
capability-package import added to `internal/fitness` should reject it, because
the import would void the very claim the test makes. Wired into the `invariants`
CI job. The suite is deliberately labelled, in package doc and in a test-guarded
doc caveat, as necessary-not-sufficient: it catches the KNOWN gaming vectors
(sibling handles via State, enforcer inputs, import direction) and D26's worked
example remains the standing reminder that a new-shape capability is the real
test, not this one.
