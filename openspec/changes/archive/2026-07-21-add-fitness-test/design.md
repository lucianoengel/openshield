## Context

The core contracts already exist and are implemented outside core: `Stage`, `Enforcer`,
`Transport`, `Ledger`. Two isolation guards also exist — `TestStageInterfaceExposesNoSiblingAccess`
(State carries data, no handles) and the `enforcerisolation` compile-fail package. `check-core-deps.sh`
bans brokers/databases from core but not concrete capability packages. T-004 produced the verdict
that the fitness test is gameable (D26). This change assembles a fitness suite and the missing
import-direction guard, and labels the whole thing with its own limits.

## Goals / Non-Goals

**Goals:**
- One test that adds a connector + stage + enforcer from outside core and flows an event through,
  proving no core edit is needed.
- A CI check that core imports no concrete capability package.
- The known gaming vectors guarded, and the T-004 "necessary but not sufficient" verdict recorded
  where a reader of the test will see it.

**Non-Goals:**
- Detecting novel end-runs (globals, singletons). A reviewer remains necessary; the suite says so.
- Re-testing capability behaviour. Shape only.

## Decisions

### The fitness test lives in its own package and imports ONLY core's public API
`internal/fitness/fitness_test.go`, package `fitness_test`. It defines a `testConnector`,
`testStage`, and `testEnforcer` locally, wires them via `core.Registry`/`core.Dispatcher`/the
`Enforcer` contract, and dispatches an event to a Decision. The discipline that makes this a
proof: the test package may import `internal/core` and `internal/core/corev1` and NOTHING from
`internal/connectors`, `internal/enforcers`, `internal/classify`, `internal/policy`,
`internal/store`. If the only way to add a capability were to reach into one of those, the test
could not be written using core alone — and it can.

### The import-direction check is a script, like the others
`scripts/check-capability-boundary.sh`: `go list -deps ./internal/core` must contain none of the
capability packages. It fails the build. This is the machine-checkable core of "adding a
capability does not edit the core": core cannot even NAME a capability, so it cannot depend on
one. Wired into the `invariants` CI job next to `check-core-deps.sh`.

### The gaming vectors are gathered, not reinvented
Rather than duplicate the existing isolation tests, the fitness suite references them by name in
a doc comment and adds the one guard they do not cover: a test asserting the import-direction
script exists and passes (so removing the script fails CI). The suite's package doc states
plainly, quoting D26, that these guards catch the KNOWN vectors and that a green suite is not
validation of the architecture.

### The honesty record is executable where possible
A test `TestFitnessTestKnowsItsLimits` asserts that the design doc / decisions reference for D26
is present (a doc-consistency check on the claim), so the "necessary but not sufficient" caveat
cannot silently disappear from the docs while the reassuring green check remains. This is a
lightweight guard against the most likely rot: the caveat being dropped while the test stays.

## Risks / Trade-offs

- **The test can be gamed exactly as D26 describes.** That is the point of labelling it. The
  mitigation is not a cleverer test — it is the paired T-004 paper verdict and a reviewer. The
  suite is honest about being necessary-not-sufficient; pretending otherwise is the failure mode.
- **The import-direction check is allowlist-shaped and could over-block.** If a future refactor
  legitimately moved a shared, capability-neutral helper, the check would flag it; that is a
  deliberate speed bump inviting a conscious decision, not an obstacle to route around — the same
  stance the State-fields test takes.
- **A doc-consistency guard on the caveat is coarse.** It checks the caveat text is present, not
  that it is correct. Coarse is enough for the failure it targets: the caveat being deleted.
