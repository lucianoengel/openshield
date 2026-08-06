# Two counters read across a goroutine boundary, and a CI that goes red on neither's account

## Why

Two tests fail intermittently in CI. Neither is a product defect. Both are the same shape: a test reads a
counter that another goroutine writes, with nothing ordering the two.

**`TestATicketDoesNotWorkFromAnotherDevice`** (`internal/gateway/socks_test.go`) dials, reads the RFC 1929
refusal, then asserts `SOCKSRefused() >= 1`. The SOCKS handler writes the refusal to the client and
increments the counter AFTERWARDS, so a client that has already read the refusal can legitimately see a
count that has not been made yet. It failed CI on `2a5b167`. The refusal itself is correct and delivered —
the security property is untouched — but the ordering is real: every refusal path in `handleSOCKS` answers
first and counts second, and the sibling CONNECT tunnel (`accesstunnel.go`) already does the opposite.

**`TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest`** (`internal/controlplane/soar2_test.go`)
asserts that the package-level `CorrelationFailures` is zero. `hunt_collision_test.go` starts a
`RunCorrelationLoop` goroutine and never waits for it to STOP: `cancel()` returns immediately, the test
finishes, `t.Cleanup(pool.Close)` runs, and the loop's next tick queries a closed pool and counts a
failure — which the next test then reads. Observed 2 failures in 6 runs today, across three agents; D484
recorded it rather than fixing it.

A flaky CI is how a team learns to ignore red. This codebase argues that in `e2e-verification` already
("a flaky integration suite is worse than none because it trains people to re-run rather than read"); it
should hold for the package suites too.

**And a product defect found underneath the second one.** Joining the leaked goroutine did not stop the
failures: under CPU load the counter still rose, and the log said `err="context canceled"`. Cancelling
the loop — which is what LOSING LEADERSHIP and SHUTTING DOWN both do — aborts whatever query is in flight,
and that error was counted as a correlation failure. `openshield_correlation_failures_total` is published
as "incidents that should have been joined were not, and an attack spanning them reads as unrelated
noise", so every demoted replica and every clean restart that landed mid-tick reported broken detection.
That is a false alarm in a deployment, not a test artifact, and it is fixed here rather than left.

## What Changes

- **Every SOCKS refusal counts BEFORE it answers**, including the method-negotiation refusal written
  inside `socksNegotiateMethod`. The class, not the one instance the test happened to observe.
- **A test that starts a background loop waits for it to have stopped** before the pool it queries is
  closed — a package-level test helper, so the next such loop inherits it.
- The assertion on `CorrelationFailures` is deliberately **NOT** reset per test. Resetting it would make
  the leak invisible instead of fixed.
- **Stopping the correlation loop no longer counts as a correlation failure**, with a test that fires the
  cancellation from inside the per-tick rules provider so the collision is deterministic.
- The roadmap's "expect intermittent CI red until a follow-up" note now points at the fix, and gains the
  gateway flake it did not record.

## Impact

- Affected specs: `network-gateway` (the count-before-answer ordering), `e2e-verification` (the
  test-hygiene rule), `cross-domain-correlation` (stopping is not failing).
- Two production changes, both to when a counter moves: `internal/gateway/socks.go` and
  `internal/controlplane/soar2.go`. No behaviour a client can observe changes, no incident is raised or
  missed differently. No migration, no proto, no dependency.
