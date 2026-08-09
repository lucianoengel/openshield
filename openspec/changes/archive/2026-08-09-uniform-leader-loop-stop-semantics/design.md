## Context

D485 (`edf8063`) fixed a metric that lied in both directions: `RunCorrelationLoop` counted its own
cancellation as `openshield_correlation_failures_total`, so a clean restart reported broken detection; the
first fix keyed the exemption on the context alone, which discarded a real database outage — count and log
both, because the log lived inside the counting branch. The shipped answer is a conjunction, extracted as
a directly-testable predicate:

```go
func isLoopStop(ctx context.Context, err error) bool {
	return ctx.Err() != nil && errors.Is(err, context.Canceled)
}
```

The conjunction is load-bearing because `internal/controlplane/leader.go:135-137` cancels `leaderCtx` when
its Postgres ping fails: a real outage produces a genuine pgx error and a cancellation in the same window,
so a context-only guard hides exactly the event the counter exists for.

**State at HEAD.** Six sibling loops never got this. In all five unfixed loops the counter increment and
the log call are SIBLINGS under one `if err != nil` — there is no counting branch yet; this change creates
it. (An earlier draft of this document described them as "logs inside the branch", which was wrong.)

| Loop | Counter | At HEAD |
|---|---|---|
| `soar2.go:132` `RunCorrelationLoop` | `CorrelationFailures` | correct (D485) |
| `beaconing.go:164` `RunBeaconLoop` | `BeaconFailures` | counts the stop; log is a sibling |
| `playbook.go:252` `RunPlaybookLoop` | `PlaybookFailures` | counts the stop; log is a sibling |
| `escalate.go:219` `RunEscalationLoop` | `EscalationFailures` | counts the stop; log is a sibling |
| `cases_http.go:330` `RunApprovalExpiryLoop` | `ApprovalExpiryFailures` | counts the stop; **no logger at all** |
| `itsm.go:170` `RunITSMLoop` | `ITSMFailures` | counts the stop; log is a sibling |
| `cmd/openshield-server/main.go:487` retention sweep | `RetentionPurgeFailures` | **seventh loop, found in review** |

All are started under `leaderCtx` from `cmd/openshield-server/main.go` (lines 254, 308, 337, 359, 464,
487, 688).

## Goals / Non-Goals

**Goals**

- One stop semantics across all seven leader loops, decided in one place rather than repeated seven times.
- Separate "not counted" from "not logged", and make the logging half actually reach a sink in production.
- Make the test helper's join usable for the scenarios that already exist, including a mid-test stop.
- Stop five test loops from leaking into the shared database.

**Non-Goals**

- No new counter, no renamed counter, no changed metric help text.
- No change to `internal/retain`.
- No change to the config-parse increments of `CorrelationFailures` / `EscalationFailures` (see
  contradiction 6).
- No attempt to make interrupted ITSM ticket creation idempotent (see contradiction 4 — recorded, not
  fixed).

## Decisions

### Decision 1 — Extend `isLoopStop` as-is rather than inventing a second predicate

`isLoopStop` is already package-scoped in `soar2.go`, already exported for tests as `IsLoopStopForTest`
(`export_test.go:260`), and already has a four-case table test
(`soar2_test.go:TestARealFailureDuringShutdownIsStillCounted`) naming both mutations. It stays where it is.

### Decision 2 — One shared error-note helper; do NOT repeat the guard at each call site

**This reverses an earlier draft of this document, which argued for inline repetition. The argument was
wrong on its own terms and is recorded here so it is not re-made.**

Add to `internal/controlplane`:

```go
// NoteTickErr records a failing tick: ALWAYS logs, counts only when the error is not this loop's stop.
// EXPORTED because the seventh loop lives in `cmd/openshield-server`, which cannot see an unexported
// helper — and that loop is the whole reason the guard went repo-wide. A free function, not a method:
// most call sites have no receiver to hang it on.
func NoteTickErr(ctx context.Context, log *slog.Logger, msg string, c *atomic.Int64, err error, attrs ...slog.Attr)
```

It defaults a nil `log` to `slog.Default()`, always emits the line with `slog.Bool("stopping", …)`
stamped, and increments `c` only when `!isLoopStop(ctx, err)`. Every loop calls it; no loop makes the
decision itself. It must log via `log.LogAttrs(ctx, slog.LevelError, msg, attrs...)` — NOT `log.Error`,
whose variadic is `...any`, so passing `slog.Attr` values degrades silently to `!BADKEY`.
`&srv.RetentionPurgeFailures` and `&srv.RetentionRecordFailures` are reachable from `cmd/` because both
fields are exported (`controlplane.go:215,:226`).

The earlier draft rejected a shared helper on the grounds that "the guard is keyed on the OUTER context,
not the one the tick receives, and a wrapper makes that invisible". That does not survive contact with the
code: `retain.DynamicLoop` passes `ctx` straight through to `fn` (`internal/retain/retain.go:41-59`), so
the two are the same value today — and if that ever changed, the inline form would be equally wrong, since
it is the same closure capture either way. Worse, the helper takes the context as an EXPLICIT first
argument, which names it at every call site; the inline `stopping := func(err error) …` closure hides the
capture instead. The helper is better on exactly the axis the rejection claimed to protect.

The second stated reason — that the five loop bodies have different shapes — argues against wrapping the
*loop*, which nothing here proposes. `NoteTickErr` wraps the error-handling three lines, which are
identical in all seven.

*Consequence:* enforcement becomes a single lexical rule (Decision 3) instead of a polarity analysis.

### Decision 3 — One lexical guard, repo-wide

Replace the earlier three-check AST guard. The rule is now: **no `*Failures.Add` may appear inside a
`retain.Loop` / `retain.DynamicLoop` function literal, anywhere in the repository.** Counting is the
helper's job; a direct increment in a loop body is by definition a site that bypassed it.

This is checkable with no polarity reasoning and no per-literal log pairing, which is what makes it sound.
The earlier Check A would have accepted `if stopping(err) { count }` (inverted) and
`if !isLoopStop(c, err)` (keyed on the tick context) as compliant — meaning requirement 1's scenarios 2
and 3 were unfalsifiable at six of seven loops. That is the defect the reviewer found and it is fatal to
the old design.

Retained verbatim from the old design: **the guard fails if its scan finds zero loops or zero increments**
— a guard that can pass by finding nothing is not a guard (the precedent is
`metrics_guard_test.go:TestEveryDeclaredCounterIsExposedOnMetrics`, which makes the same check).

Scope is repo-wide because the seventh loop is in `cmd/` (contradiction 2). Verified non-test call sites of
`retain.Loop`/`retain.DynamicLoop`: **14** — 6 in `internal/controlplane`, 1 in `internal/posture`, 7 in
`cmd/` (`engine:118`, `server:330/390/487/707/735`, `gateway:108`). Of those, only `server:487` increments
a failure counter outside `internal/controlplane`.

### Decision 4 — The test helper takes the pool as a guardrail, NOT as a proof

`requireDB` registers `t.Cleanup(pool.Close)` (`controlplane_test.go:61`) before returning the pool, so for
pools obtained that way, a helper requiring the pool as an argument cannot be called before the close is
scheduled, and LIFO puts the join first.

**But the claim that this is structural is false in this package, and the earlier draft asserted it
anyway.** `leader_test.go:17-21` builds a second pool released by `defer pool2.Close()` — and a `defer` in
the test body runs BEFORE any `t.Cleanup` — while `signed_test.go:18-25`'s `mustPoolCP` registers no
release at all. Possessing a pool argument therefore does not prove its close was scheduled, let alone
scheduled earlier.

So: the parameter stays as a guardrail, the prose is downgraded to "makes the common mistake harder", and
the spec scenario that asserted the guarantee is REMOVED — a signature is not a behaviour, and a scenario
that cannot fail is the thing this project keeps writing requirements against. The ordering is instead
verified by an actual leak test (task 4.8).

*Alternative considered and deferred:* have `requireDB` return a fixture owning both the pool and a
`StartLoop` method, so no pool lacking a close is reachable. That is the real guarantee, but `requireDB`
returns `*pgxpool.Pool` to **285** call sites across the package; changing its return type is a
larger and riskier change than the defect warrants and would swamp this one. Recorded on the roadmap
instead (task 7.5).

*Also dropped:* the earlier task to defend the unused parameter with a comment. `go vet` is the only lint
gate here and does not flag unused parameters, so the comment was defending against a risk that no tool
raises.

### Decision 5 — Build a real logger in the server command and default nil at the loop

`cmd/openshield-server/main.go` does not import `log/slog` at all. (Grepping for `slog` in that file
returns eight hits; every one is a substring of `syslog`. The earlier draft's task 2.6 — "use the logger
value the call site gives" — therefore resolved to `nil`.) Every loop is handed a literal `nil`, and every
log call in every loop body is wrapped in `if log != nil`. **D485's `LOGGED EVEN WHEN NOT COUNTED` block
at `soar2.go:167-171` has consequently never emitted a line in production**, and the new logging
requirement would have shipped as a no-op.

Both ends are fixed: `NoteTickErr` defaults nil to `slog.Default()` so the record cannot be lost by a
caller's omission, and `main.go` constructs `slog.New(slog.NewTextHandler(os.Stderr, nil))` — the pattern
at `cmd/openshield-engine/main.go:87` and `cmd/openshield-fleet-agent/main.go:316` — and passes it to all
seven loops. A wiring test modelled on `cmd/openshield-engine/enforce_wiring_test.go` asserts the binary
does this, because a requirement enforced only against a function signature is one production can satisfy
with `nil`.

### Decision 6 — ITSM distinguishes the one phase whose interruption leaves remote state

See contradiction 4. The naive version of this — "tag the line create vs poll" — has no mechanism:
`SyncITSM` (`itsm.go:29-37`) returns `openTickets`'s and `syncTicketStatuses`'s errors indistinguishably,
so the loop cannot tell them apart, and an implementer would have to invent something or quietly drop the
attribute.

It is also the wrong distinction. A failed POST is harmless — nothing was created, and the next tick
retries. The dangerous window is narrower: **after `CreateTicket` returned 2xx and before the `INSERT` at
`itsm.go:93`**, which leaves a real ticket in someone else's queue with no local link, and the next tick's
`NOT EXISTS` opens a second one.

Mechanism: `SyncITSM` wraps each half's error with `%w` against a distinguishable sentinel, and
`openTickets` wraps the post-POST insert failure specifically — `ErrTicketUnlinked`. Both `fmt.Errorf`
with `%w` and `*url.Error` preserve `errors.Is(err, context.Canceled)`, so the stop exemption is
unaffected by the wrapping. The line then states the actionable fact — a remote ticket exists with no
local link — rather than an undifferentiated phase label.

### Decision 7 — Extract `startLeaderLoops` so the wiring test is real rather than lexical

`cmd/openshield-engine/enforce_wiring_test.go` works because `registerEnforcers` is a factored function.
The server has no equivalent: its loop startup is inline in `main()`'s `onElected` block spanning
`main.go:254-740`, interleaved with NATS, TLS and listener setup, and is not drivable in-process. A
wiring test written against it today degrades to parsing `main.go` for nil literals — asserting source
text, not "a logger the process actually writes through".

So the seven loop starts move into `startLeaderLoops(leaderCtx, srv, cfg, log, deps)`, with `deps`
carrying the locally-built values they need (the ITSM connector, the sink order, the ladder loader, the
retention jobs). This puts the seven call sites in one reviewable place and makes the wiring genuinely
testable.

The spec scenario was ALSO reworded into its two independently falsifiable halves — "no call site is
handed an absent logger" and "a loop handed none still records via the default" — so the requirement does
not depend on this extraction succeeding. If the extraction turns out to require moving unrelated setup,
the implementer stops and keeps the two halves (task 3.5 says so explicitly). A scenario whose stated
guarantee only one branch delivers is the failure mode being avoided.

## Contradictions and corrections to the ticket as described

1. **The ticket says four leaking test loops; there are five.** `nips6_test.go` has TWO unjoined
   `go srv.RunBeaconLoop(...)` calls — `:197` (`TestBeaconLoopSweepsOnItsOwnSchedule`, the 20ms one) and
   `:226` (`TestAZeroIntervalLeavesTheSweepIdle`). The roadmap names only `:197`; D485's commit message
   says five, and the commit message is right.

2. **The ticket says six leader loops; there are seven — and the seventh counts TWICE.**
   `cmd/openshield-server/main.go:487` runs `retain.Loop(leaderCtx, retInterval, …)` whose failure path
   increments `RetentionPurgeFailures` (`main.go:516`, via `runRetentionSweep`). It is under `leaderCtx`
   and counts its own cancellation. A requirement written as universal would have been violated by this
   repo on the day it landed, with a package-scoped guard reporting green.

   The same loop literal also reaches `RetentionRecordFailures` — `runRetentionSweep` calls
   `record(ctx, …)` at `main.go:1480`, which is `srv.RecordRetentionEvent`, whose `pool.Exec` failure
   increments the counter at `internal/controlplane/retention_report.go:35` and reports via
   `fmt.Fprintf(os.Stderr, …)` with no `stopping` stamp. On a stop mid-sweep that `Exec` fails with
   `context.Canceled` and the counter moves — precisely what Requirement 1 forbids, on a counter published
   as `openshield_retention_record_failures_total`. Both are in scope.

   **This is also the limit of the lexical guard**, and the spec now says so: the increment at
   `retention_report.go:35` is inside a METHOD CALLED FROM the loop literal, not inside the literal, so no
   lexical rule can see it. The obligation is universal; the build-time check is not. Requirement 1
   carries that caveat explicitly rather than implying the guard is exhaustive.

3. **`cases_http.go:330` is a signature change reaching `cmd/`, not a one-line addition** —
   `RunApprovalExpiryLoop` has no logger parameter at all.

4. **The safety argument is false for ITSM's create path, and the ticket inherits it from the code.**
   `itsm.go:74-95` calls `conn.CreateTicket` (an unkeyed POST) and only then writes the local link row. A
   stop landing between the remote 2xx and the `INSERT` leaves a real ticket in someone else's queue with
   no local record; the next tick's `NOT EXISTS` re-selects the incident and opens a second one.
   `ON CONFLICT DO NOTHING` protects the local table, not the remote system, and the comment at
   `itsm.go:90-91` ("a failed attempt simply retries with no duplicate risk") is true only for a failure
   INSIDE `CreateTicket`. The exemption is still correct — this is not a reason to page on every restart —
   but the "interrupted work is re-attempted" paragraph is qualified in the spec, the log names the phase
   (Decision 6), and "ITSM ticket creation is not idempotent across a leader handover" goes to the roadmap
   as its own entry (task 7.4). **Not fixed here.**

5. **`soar4_test.go:594` cannot leak, and is still in scope.** It starts with an already-cancelled context,
   so `DynamicLoop` returns on its first select. Join it for uniformity; do not claim it fixes a live
   defect.

6. **Minor 14 generalises: TWO counters mix ticks with config parses, not one.** The reviewer flagged
   `EscalationFailures` being incremented at `main.go:699` for a ladder parse failure. `CorrelationFailures`
   has the same shape at `main.go:281` for a hunts-file parse failure. Both increments are correct and are
   left alone, but they mean those two series are not purely "ticks that failed". Acknowledged in the
   requirement text rather than silently contradicted; roadmap note in task 7.6.

7. **`nips6_test.go:197` is the DDL/DML collision.** `requireDB` executes `DROP TABLE … CASCADE` over ~35
   tables followed by `postgres.Migrate` (`controlplane_test.go:55-60`). A leaked beacon sweep reading and
   writing `unified_alerts` every 20ms during that window fails on a missing or half-created relation, and
   the failure surfaces in whichever test `requireDB` was serving.

8. **The obvious per-loop test passes vacuously, and the fix for that is itself racy if written naively.**
   `retain.DynamicLoop` re-checks `ctx.Err()` before calling `fn` (`retain.go:53-55`), so cancelling from
   outside almost never lands inside a tick. The deterministic seam is to **cancel from inside a per-tick
   provider the loop itself calls** — but that provider runs on the LOOP's goroutine, so reading a counter
   or a log buffer from the test goroutine without joining is a data race (`-race` will fail on the
   buffer) and a premature read (on the counter). Every such test must therefore join the loop goroutine
   before asserting and use a mutex-guarded log sink. The correct model already exists in-repo at
   `soar2_test.go:112-135`. Per-loop seams, all verified reachable:
   - `RunBeaconLoop`: cancel inside `rule()`, evaluated in the argument list of `s.DetectBeaconing(c, rule(), …)`.
   - `RunPlaybookLoop`: cancel inside `playbooks()`, returning a non-empty slice so the early return is not taken.
   - `RunEscalationLoop`: cancel inside `ladder()`, returning **at least one rung** — `Escalate` returns
     `(0, nil)` immediately when `len(l.Rungs) == 0` (`escalate.go:135-137`), so an empty ladder makes the test vacuous.
   - `RunApprovalExpiryLoop`: no provider inside `fn`, so cancel inside the SECOND `interval()` evaluation
     — `DynamicLoop` calls `next()` twice per iteration and the second call is after its `ctx.Err()` guard.
   - `RunITSMLoop`: cancel from inside the `httptest` handler, which then blocks on `<-r.Context().Done()`
     so the in-flight request deterministically fails with a `*url.Error` wrapping `context.Canceled`.

9. **A context-only guard is still live in the same file, on the logging half.**
   `cmd/openshield-server/main.go:526`, `:568`, `:577`, `:589` use `err != nil && leaderCtx.Err() == nil`
   to decide whether to REPORT a listener failure — the exact construct D485 declared unsafe, applied to
   the record rather than the count, so a genuine listener failure during shutdown is silent. This is the
   same defect class in the same file and it is NOT in scope here: those are listeners, not counted
   scheduled loops, and folding them in would widen a change that already grew from six loops to seven
   plus a logger rewire. Recorded on the roadmap as its own entry (task 7.7) with this reasoning.

## Risks / Trade-offs

- **[Five counters stop moving on restarts]** → Intended, and matches what `correlation_failures_total`
  has done since D485. No metric renamed, so no dashboard breaks.
- **[The new logger makes the server noisy]** → Only failing ticks log, and they logged nothing before
  because the logger was nil. If volume is a problem the answer is the handler's level, not dropping the
  line.
- **[`slog.Default()` as the fallback writes somewhere nobody reads]** → It is strictly better than the
  current silence, and the wiring test plus the `cmd/` change mean the fallback is a backstop rather than
  the normal path.
- **[The repo-wide guard produces false positives in `cmd/`]** → The rule is lexical and narrow: a
  `*Failures.Add` inside a `retain.Loop`/`DynamicLoop` literal. The one legitimate-looking case,
  `main.go:516`, is a genuine violation being fixed. Config-parse increments (`main.go:281`, `:699`) sit in
  provider closures, not loop literals, so the guard does not see them — which is correct, since they are
  not ticks.
- **[`NoteTickErr` becomes a dumping ground]** → Its signature is fixed at (ctx, log, msg, counter, err,
  attrs) and it does exactly three things. A loop needing more should call it and then do the more.

## Migration Plan

No data migration, no schema change, no config change. Behaviour changes on deploy. Rollback is a revert;
nothing persists that would need undoing.

## Open Questions

1. **Should `RunITSMLoop` move to `retain.DynamicLoop` while it is being touched?** Its interval is
   captured once at leader startup, so `OPENSHIELD_ITSM_INTERVAL` is a stored, console-editable setting
   that silently needs a restart — the defect D292 fixed for playbooks. **Out of scope; do not fix here**
   (task 7.3).
2. **Should the listener-logging guards (contradiction 9) be fixed in this change?** Assessed and
   deliberately excluded, with reasoning recorded above. If the owner disagrees it is a two-line change
   per site.
3. **Should `requireDB` become a fixture that owns both ends (Decision 4)?** Deferred on blast radius.
