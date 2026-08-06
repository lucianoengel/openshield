# Design — fixing the race, not the assertion

## Flake 1: count before answering, rather than teaching the test to wait

Two fixes were available.

**Rejected — poll the counter in the test.** It keeps production ordering and it would work. It is
weaker for two reasons. First, a test that polls cannot distinguish "counted late" from "counted after an
unbounded delay", so the only thing it can assert is *eventually*; the property an operator relies on is
that a refusal a client has already received is already in the count, and *eventually* does not say that.
Second, it leaves the ordering in place on eight other refusal paths, where the next test to observe a
counter would have to learn the same lesson and add the same poll. The flake would move, not go.

**Taken — increment before the write.** It makes the assertion sound by construction: the `Add` happens
before the bytes go out, the bytes go out before the client reads them, so a client holding the refusal is
holding proof the count was made. It also makes SOCKS match the CONNECT tunnel next to it, which has
counted first since it was written — the SOCKS handler was the deviation.

**The class, not the instance.** Nine refusal paths in `handleSOCKS` write a reply; every one of them
counted afterwards. One of those writes is not in `handleSOCKS` at all — `socksNegotiateMethod` writes the
`0xFF` "no acceptable method" itself and returns an error for the caller to count. Passing the counters
into that helper is slightly less pure than leaving it a protocol function, and it is the only way the
invariant can hold there: the caller cannot count before a write it does not perform. The helper now owns
counting for every failure it can produce, so the caller counts none of them and neither double-counts.

**What this does not fix.** The reverse direction is untouched and unfixable this way: nothing stops a
counter being read before the refusal is *delivered*, only before it is *observed*. That is the only
ordering any test here needs.

**Honest limit on the test.** The assertion is exact after the fix, but it can only PROBABILISTICALLY
detect the fix's absence — restoring the old order leaves a window measured in microseconds. Mutation
runs are therefore reported as a rate, and a second mutation that widens the window with a sleep is run
to show the assertion is detecting the ORDER and has not gone vacuous.

## Flake 2: stop the goroutine, do not reset the counter

The leaked loop is the defect. `defer cancel()` looks like it stops the loop, and it only *asks*: it
returns while the goroutine may be mid-`Exec`, and Go runs the test's `t.Cleanup(pool.Close)` after the
deferred calls. Whether the tick lands before or after the pool closes is a scheduling coin flip, and
when it lands after, the loop writes to a package-level counter that outlives every test in the binary.

**Rejected — reset `CorrelationFailures` at the start of the asserting test.** It makes the symptom go
away and it makes the test blind: a leaked loop in any other test would then be masked rather than
reported, which is exactly the state that let this one reach CI. It also fails the vacuity test — with
the counter reset, re-leaking the goroutine does not fail anything, so the "fix" would be indistinguish-
able from deleting the assertion.

**Taken — the test waits for the loop to have returned.** `startCorrelationLoop` registers a cleanup that
cancels and then blocks on the goroutine's `done` channel (with a bounded wait that FAILS the test rather
than hanging it). Registered after `requireDB`, so LIFO cleanup order puts the join strictly before
`pool.Close` — the pool cannot close under a running query.

**The un-reset counter is then a leak detector for the whole package**, which is the property that caught
this. A future test that leaks a loop fails `TestScheduledCorrelation…` with "reported N failures", which
is a strange place to learn it — so the assertion now says in its own message that a non-zero count may
belong to someone else's loop.

## The leak was only half of flake 2 — the other half is a product defect

Joining the goroutine was necessary and not sufficient. With the join in place and 24 CPU burners
running, the counter still rose: `err="context canceled"`. Cancelling the loop aborts the query it is
inside, and that error was counted.

This is worth separating from the test hygiene around it, because it is not a test problem. The loop runs
in the leader's context; losing leadership and shutting down BOTH cancel it, and both are routine. So
`openshield_correlation_failures_total` — documented as "incidents that should have been joined were not"
— went up on ordinary operations. An operator who sees that metric rise on every restart stops reading it,
and then it cannot do the job it exists for.

The fix suppresses the count only when `ctx.Err() != nil`, checked per call because the cancellation can
land between any two of them. Nothing actionable is lost: the loop is exiting, the tick will not be
retried by this process, and no response is available to whoever the alarm reaches. The alternative —
matching on `errors.Is(err, context.Canceled)` — was rejected because it would also swallow a cancellation
that came from somewhere else entirely, which IS a real fault; asking whether THIS loop is stopping is the
precise question.

**Making the test for it deterministic mattered more than usual.** Written the obvious way (tiny interval,
cancel, hope the stop lands mid-query) it killed the mutation 6 times in 10 — a test that is flaky in the
direction of PASSING, which is what this whole change exists to remove. Firing the cancellation from
inside the per-tick rules provider makes the collision certain: every query in that tick then runs on a
context that is already done. The first tick is left alone and its incident asserted, so the test cannot
pass by virtue of a loop that did nothing. Mutation now kills 10 of 10.

## Why the delta is split across three capabilities

`e2e-verification` owns suite hygiene and recently gained the per-test-resource requirement, which is the
same species: a convention nobody enforces, failing only when the whole suite runs. The goroutine rule
belongs there.

The SOCKS ordering does not. It is a change to shipped behaviour in `internal/gateway`, and
`network-gateway` already REQUIRES that these refusals be counted ("the refusal is counted", "Tunnels
refused … SHALL be counted and surfaced where the gateway already reports"). What was missing is WHEN,
and the natural home for that is beside the requirement it qualifies. Putting a production ordering rule
under a verification capability would make it invisible to anyone reading the gateway's spec, which is
where the next person to write a refusal path will look.

The "stopping is not failing" rule goes to `cross-domain-correlation`, which already owns the requirement
that the loop runs on a clock and that a failing hunt is counted and named. It qualifies that counting
rule, so it belongs beside it.

A further option — a new capability for "counters" — was rejected: three requirements do not need a
capability, and each has an existing owner.

## Why this class always surfaces in CI first

Both flakes pass under a targeted `-run`. The gateway window opens under `go test -race ./...` with the
whole tree competing for cores; the correlation one needs another test in the same binary to have run
first. The project rule is to run targeted tests locally, so this class is structurally invisible there.
That is an argument for making each instance impossible, not for running broader suites.
