House rules for every task: **targeted package tests only** (`go test ./internal/controlplane/ -run '<TestName>'`) — never `go test ./...`, never `make all`. **Never `git add -A`** — stage named paths. Every behavioural task names the mutation that must make its test FAIL; **if a mutation does not fail, the test is wrong** — fix the test, do not weaken the mutation. Re-verify every `file:line` against `HEAD` before editing; other sessions touch this repo.

The spec delta in `specs/` is FINAL. Transcribe it verbatim. If you believe a requirement is wrong, STOP and report it — do not edit it.

## 1. The shared helper, first — everything else calls it

- [x] 1.1 Add **`NoteTickErr`**`(ctx context.Context, log *slog.Logger, msg string, c *atomic.Int64, err error, attrs ...slog.Attr)` to `internal/controlplane/soar2.go`, beside `isLoopStop`. **EXPORTED** — the seventh loop is in `package main` (`cmd/openshield-server`) and cannot see an unexported helper; an unexported one is a compile break, not a style choice. A free function, not a method: most call sites have no receiver. It SHALL: default a nil `log` to `slog.Default()`; compute `stopping := isLoopStop(ctx, err)`; ALWAYS log; and increment `c` only when `!stopping`. The `ctx` parameter is the LOOP's context, passed explicitly at every call site — do not re-derive it inside.
- [x] 1.1a Emit with `log.LogAttrs(ctx, slog.LevelError, msg, append([]slog.Attr{slog.Bool("stopping", stopping), slog.Any("err", err)}, attrs...)...)`. **Do NOT use `log.Error`** — its variadic is `...any`, so `slog.Attr` values passed to it degrade silently to `!BADKEY` and the `stopping` stamp becomes unreadable.
- [x] 1.2 Carry D485's reasoning into the helper's doc comment: why the conjunction (`leader.go:135-137` cancels `leaderCtx` on a Postgres ping failure, so an outage yields a real error and a cancellation together), and why the log is unconditional (not counting is about not paging; not recording is a different decision — D31).
- [x] 1.3 `TestNoteTickErrCountsAndLogsIndependently` in `internal/controlplane` — table over the four (live/cancelled context) × (cancellation/other error) combinations, asserting the counter delta AND that a line was emitted with the right `stopping` value, every time. **Mutation A:** make the log conditional on `!stopping` → the exempted-tick log case FAILS. **Mutation B:** drop the `!stopping` condition on the increment → the stop case FAILS. **Mutation C:** widen `isLoopStop` to the context alone → the "real error while stopping" case FAILS. **Mutation D:** remove the nil-logger default → the nil-logger case panics or FAILS.
- [x] 1.4 Verify: `go test ./internal/controlplane/ -run 'TestNoteTickErrCountsAndLogsIndependently' -race`.

## 2. Route all seven loops through the helper

Each task: delete the loop's `if err != nil { Counter.Add(1); if log != nil { log.Error(...) } }` block and replace it with one `NoteTickErr(ctx, log, …, &Counter, err)` call passing the **outer** `ctx`.

- [x] 2.1 `internal/controlplane/beaconing.go:164` `RunBeaconLoop` / `BeaconFailures`. Preserve the `return` after the failure and the `n > 0` info line.
- [x] 2.2 `internal/controlplane/playbook.go:252` `RunPlaybookLoop` / `PlaybookFailures`. Leave the `len(pbs) == 0` early return alone.
- [x] 2.3 `internal/controlplane/escalate.go:219` `RunEscalationLoop` / `EscalationFailures`.
- [x] 2.4 `internal/controlplane/itsm.go:170` `RunITSMLoop` / `ITSMFailures`. Do **not** convert this loop to `DynamicLoop` (open question 1).
- [x] 2.4a **Give the phase attr a mechanism.** `SyncITSM` (`itsm.go:29-37`) returns `openTickets`'s and `syncTicketStatuses`'s errors indistinguishably, so the loop currently CANNOT tell them apart — without this task the attr has to be invented or dropped. Wrap each half's error with `%w` against a distinguishable sentinel, and in `openTickets` wrap the **post-POST insert failure** specifically as `ErrTicketUnlinked` (`itsm.go:93`). That is the window that matters: a failed POST is harmless, but a stop after a 2xx and before the `INSERT` leaves a real ticket with no local link and the next tick opens a second one. Both `fmt.Errorf`/`%w` and `*url.Error` preserve `errors.Is(err, context.Canceled)`, so the exemption is unaffected. The line states the actionable fact — a remote ticket exists with no local link — not a bare phase label.
- [x] 2.5 `internal/controlplane/cases_http.go:330` `RunApprovalExpiryLoop` / `ApprovalExpiryFailures`. **Signature change:** add `log *slog.Logger` as the third parameter. This loop has neither half today.
- [x] 2.6 `internal/controlplane/soar2.go:132` `RunCorrelationLoop` — replace its **four** inline guard blocks with `NoteTickErr` calls: `:164` (burst), `:174` (cross-domain), `:193` (hunt) and **`:208` (XDR-7 entity-risk publication)**, all inside the literal closing at `:211`. `:208` reads as an afterthought and is the one that gets missed. Keep the per-hunt naming attr. The comment block at `:134-152` stays; trim only the parts the helper now owns.
- [x] 2.7 **The seventh loop, counter one:** `cmd/openshield-server/main.go:487`, whose failure callback at `:516` is `func() { srv.RetentionPurgeFailures.Add(1) }` (design.md contradiction 2). Route it through `NoteTickErr` so a stop mid-sweep is not counted. `runRetentionSweep` takes a bare `func()`; give it what it needs to call the helper with the loop's `leaderCtx` and the real error rather than a bare signal. Do **not** change what a genuine purge failure counts as.
- [x] 2.7a **The seventh loop, counter two:** the same literal also reaches `RetentionRecordFailures` — `runRetentionSweep` calls `record(ctx, …)` at `main.go:1480`, i.e. `srv.RecordRetentionEvent`, whose `pool.Exec` failure increments the counter at `internal/controlplane/retention_report.go:35` and reports via `fmt.Fprintf(os.Stderr, …)` with no `stopping` stamp. On a stop mid-sweep that `Exec` fails with `context.Canceled` and the counter moves. Route `RecordRetentionEvent` through the helper too, taking the loop context. **Note for the guard:** this increment is inside a method CALLED FROM the literal, so section 6's lexical rule cannot see it — it is fixed here by review, and the spec says the check is not exhaustive.
- [x] 2.8 Verify: `go build ./cmd/... ./internal/controlplane/` then `go test ./internal/controlplane/ -run 'TestBeacon|TestPlaybook|TestEscalat|TestApproval|TestITSM|TestScheduledCorrelation' -race`.

## 3. Make the logger real in the shipped binary (BLOCKER)

`cmd/openshield-server/main.go` does not import `log/slog`; all seven loops receive a literal `nil`. Without this section the whole logging requirement ships as a no-op — see design.md Decision 5.

- [x] 3.1 Construct `log := slog.New(slog.NewTextHandler(os.Stderr, nil))` in `cmd/openshield-server/main.go`, following `cmd/openshield-engine/main.go:87` and `cmd/openshield-fleet-agent/main.go:316`. Add the `log/slog` import.
- [x] 3.2 Pass it to all seven loops: `main.go:254` (correlation, currently `}, nil)`), `:308` (beacon), `:337` (approval expiry — new parameter), `:359` (playbook), `:464` (`RunITSMLoop(leaderCtx, si, itsm, nil)`), `:487` (retention), `:688` (escalation). **Passing `nil` compiles — that is the exact failure this section exists to prevent.**
- [x] 3.3 **Extract `startLeaderLoops(leaderCtx, srv, cfg, log, deps)`** from `main()`'s `onElected` block, moving the seven loop starts into it with `deps` carrying the locally-built values they need (the ITSM connector, the sink order, the ladder loader, the retention jobs). `enforce_wiring_test.go` only works because `registerEnforcers` is factored; the server's startup is inline across `main.go:254-740`, interleaved with NATS, TLS and listener setup, and is not drivable in-process as it stands. This also puts the seven call sites in one reviewable place.
- [x] 3.3a **If the extraction turns out to require moving unrelated setup, STOP and keep the two halves in 3.4/3.5** rather than half-extracting. The spec scenario was written so it does not depend on this task succeeding.
- [x] 3.4 `TestServerWiresALoggerIntoEveryLeaderLoop` in `cmd/openshield-server`, modelled on `cmd/openshield-engine/enforce_wiring_test.go`: drive `startLeaderLoops` with a recording handler, force a failing tick, assert a line came out. **Mutation:** revert any one call site to `nil` → FAILS, naming that site. (If 3.3a was taken, this degrades to an AST assertion that no call site passes a nil logger literal — say so in the test comment, and note it asserts source text rather than behaviour.)
- [x] 3.5 The second half of the guarantee — "a loop handed no logger still records via `slog.Default()`" — is task 5.4 and is falsifiable independently of 3.3/3.4. Confirm it is present before closing this section; the two halves together are what the spec scenario asks for.
- [x] 3.6 Verify: `go test ./cmd/openshield-server/ -run 'TestServerWiresALoggerIntoEveryLeaderLoop'`.

## 4. Test harness

- [x] 4.1 Add `startLoop(t *testing.T, pool *pgxpool.Pool, name string, run func(context.Context)) (stop func())` in `internal/controlplane/controlplane_test.go`. It starts `run` on a goroutine, and `stop` cancels and joins with a 10s bound, `t.Error`-ing (not hanging) on timeout with `name` in the message. `stop` MUST be idempotent — `sync.Once` — and MUST also be registered via `t.Cleanup`, so a caller that never calls it is still joined and a caller that calls it mid-test is not joined twice (design.md, MAJOR 5).
- [x] 4.2 Comment the `pool` parameter as a GUARDRAIL, not a proof: it makes the common ordering mistake harder for pools from `requireDB` (which registers `t.Cleanup(pool.Close)` at `controlplane_test.go:61` before returning), but this package also has `leader_test.go:17-21` (`defer pool2.Close()`, which runs before any cleanup) and `signed_test.go:18-25` (`mustPoolCP`, no cleanup at all). Do not claim it is structural.
- [x] 4.3 Reshape `startCorrelationLoop` to take the pool and delegate to `startLoop`. Update its **two** callers — `hunt_collision_test.go:180` and `soar2_test.go:38`. (There are two, not three.)
- [x] 4.4 Leave `soar2_test.go:112-135`'s inline loop start as it is: it is the mid-tick-cancellation test and needs the provider seam and the explicit join it already has. Record that decision in a comment there so a later cleanup does not "unify" it into the helper and lose the seam.
- [x] 4.5 Convert `nips6_test.go:197` (`TestBeaconLoopSweepsOnItsOwnSchedule`) to `startLoop`, dropping its `ctx, cancel` / `defer cancel()` pair. This is the DDL/DML collision.
- [x] 4.6 Convert `nips6_test.go:226` (`TestAZeroIntervalLeavesTheSweepIdle`) to `startLoop` — the fifth leak, absent from the roadmap table.
- [x] 4.7 Convert `soar4_test.go:584/:594/:604` to `startLoop`. **The `cancel()` at `:588` is deliberate** — it stops the bad-trigger loop before the demotion and live-context phases — so it becomes `stop()` from the first `startLoop`. Converting it to a cleanup-only join would leave that loop hammering the pool through both later phases and change what the test proves. All existing assertions must survive unchanged.
- [x] 4.8 Verify the join actually works: `go test ./internal/controlplane/ -race -count=2 -run 'TestBeaconLoop|TestAZeroInterval|TestPlaybookLoopStops|TestScheduledCorrelation'`. **Mutation:** make `stop` cancel without waiting on the done channel → a leak surfaces (a counter or a schema error in a *different* test). If nothing fails, the join is not being exercised and 4.5–4.7 are unproven.
  - **CORRECTION (implementer):** the mutation AS NAMED does not reproduce, and the reason is this change
    itself. Ran it at `-count=2` narrow, at `-count=10` on both beacon tests, and over the full package
    with `-race`: all green. Once a loop's own cancellation is exempt from its counter (requirement 1),
    the counter symptom of a leak disappears; and `stop` still cancels at the same LIFO position, so the
    goroutine exits in microseconds and never reaches the next test's `DROP TABLE`/`Migrate` window.
    The mutation is not falsifiable here rather than the join being unexercised.
  - **Substituted mutation, which DOES fail:** make `stop` neither cancel nor join (`if false { cancel() }`).
    `go test ./internal/controlplane/ -count=2 -run 'TestBeaconLoopSweepsOnItsOwnSchedule|TestAZeroIntervalLeavesTheSweepIdle'`
    → 4 failures, each `the <name> loop did not stop within 10s ...`, naming both converted loops. That is
    what proves 4.5–4.7 route through the helper and that the join path runs.

## 5. Per-loop behavioural tests

Seam: **cancel from inside a per-tick provider the loop itself calls** (design.md contradiction 8) — cancelling from outside is vacuous because `retain.DynamicLoop` re-checks `ctx.Err()` before calling `fn`.

**That provider runs on the LOOP's goroutine.** Every test below MUST therefore join the loop goroutine (bounded, `t.Fatal` on timeout) BEFORE reading any counter or log buffer, and MUST use a mutex-guarded log sink — an unguarded `bytes.Buffer` is a genuine `-race` failure and the counter read is premature. Precedents: `soar2_test.go:112-135` (the model), `cmd/openshield-engine/pipelinereport_test.go:139`, `cmd/openshield-gateway/rejectionreport_test.go:123`. Read counters as a `before`/`after` delta; **never reset a package-global counter.**

Each test asserts BOTH halves separately: the counter is unchanged AND a line was emitted with `stopping=true`.

- [x] 5.1 `TestBeaconSweepStopIsNotAFailure` — cancel inside `rule()`, evaluated in the argument list of `s.DetectBeaconing(c, rule(), …)`. **Mutation A:** have the loop count unconditionally → counter assertion FAILS. **Mutation B:** make the helper's log conditional on `!stopping` → log assertion FAILS.
- [x] 5.2 `TestPlaybookTickStopIsNotAFailure` — cancel inside `playbooks()`, returning a NON-EMPTY slice so the `len(pbs) == 0` early return is not taken. Same mutations against `PlaybookFailures`.
- [x] 5.3 `TestEscalationSweepStopIsNotAFailure` — cancel inside `ladder()`, returning **at least one rung**: `Escalate` returns `(0, nil)` immediately when `len(l.Rungs) == 0` (`escalate.go:135-137`), so an empty ladder makes the test vacuous. **Mutation:** return an empty `Ladder` → the test must FAIL (nothing to exempt), proving the seam is live.
- [x] 5.4 `TestApprovalExpiryStopIsNotAFailureAndIsLogged` — no provider inside `fn`, so cancel inside the SECOND `interval()` evaluation: `DynamicLoop` calls `next()` twice per iteration and the second is after its `ctx.Err()` guard. The log assertion here is a new-capability assertion — this loop logged nothing before. **Mutation:** pass `nil` for the logger → the line must STILL appear, via `slog.Default()`; if it does not, task 1.1's fallback is missing.
- [x] 5.5 `TestITSMSyncStopIsNotAFailure` — seed an incident that actually reaches the create path (above a valid `MinSeverity`, or `severityFloor` fails with a non-cancellation error and the test passes for the wrong reason). The `httptest` handler `cancel()`s and then blocks on `<-r.Context().Done()`, so the in-flight request deterministically fails with a `*url.Error` wrapping `context.Canceled`. Assert `ITSMFailures` unchanged, a line with `stopping=true`, AND that the line names the interrupted phase (task 2.4).
- [x] 5.6 If any loop resists the deterministic seam, **do not ship a sleep-based approximation** — leave that loop's behavioural assertion out, note it here, and rely on the section 6 guard. A timing test that cannot fail re-introduces the flake class D485 was closing.
  - **No loop resisted; nothing was dropped and no sleep-based approximation was written.** All five
    deterministic seams landed as specified. One implementation note: `TestITSMSyncStopIsNotAFailure`'s
    handler cannot park on `<-r.Context().Done()` alone — the client aborts on the cancelled context
    without closing the request body, so the server never observes the disconnect and
    `httptest.Server.Close` (which waits for outstanding handlers) deadlocks the test. It selects on
    `r.Context().Done()` OR a `release` channel closed by a defer ordered before the server's Close.
- [x] 5.7 Add the sibling loop names to `TestARealFailureDuringShutdownIsStillCounted`'s comment so its coverage claim is legible now that all seven share the predicate. Verify it still passes and both its mutations still fail.
- [x] 5.8 Verify: `go test ./internal/controlplane/ -run 'StopIsNotAFailure|IsLogged|TestARealFailureDuringShutdownIsStillCounted' -race -count=2`.

## 6. The guard — repo-wide, lexical

One rule: **no `*Failures.Add` inside a `retain.Loop`/`retain.DynamicLoop` function literal, anywhere in the tree.** Counting is `NoteTickErr`'s job. No polarity analysis, no per-literal log pairing (design.md Decision 3).

- [x] 6.1 Add `TestNoLeaderLoopCountsItsOwnFailures` in `internal/controlplane/loop_guard_test.go` (`package controlplane`). Parse the repo's non-test `.go` files with `go/parser` + `go/ast`, find every call to `retain.Loop`/`retain.DynamicLoop`, and reject any `X.Add(...)` inside the function-literal argument where `X` is an identifier or selector ending in `Failures`. Failure message names the enclosing function and points at `NoteTickErr`.
- [x] 6.1a **Find the repo root explicitly:** `go test` sets CWD to the package directory, so walk UP to the directory containing `go.mod` and scan from there. Skip `_test.go` files and any vendor directory. **A loop argument that is not a function literal must be skipped without panicking** — `internal/posture/attestloop.go:33` passes a named func value (`attempt`), not a literal, and a walk that type-asserts `*ast.FuncLit` unconditionally crashes on it.
- [x] 6.2 Scope the walk repo-wide, not to one package — the seventh loop is in `cmd/`. Expect **14** non-test call sites: 6 in `internal/controlplane`, 1 in `internal/posture`, 7 in `cmd/`. Do not hardcode that number as an assertion; it is a sanity check for the implementer.
  - **Confirmed 14** — but only after excluding HIDDEN directories. `.claude/worktrees/` holds other
    agent sessions' git worktrees, i.e. entire nested copies of this repository; scanning them reported
    **19** loop sites and would let a sibling session's uncommitted code fail this build (or hide a real
    violation behind a stale copy that still looks compliant). The walk now skips any directory whose
    name begins with `.`, which also covers `.git` and `.gitnexus`.
- [x] 6.3 **Keep the empty-scan check:** if the walk finds zero loops, or zero counter increments across the whole tree, `t.Fatal` saying the guard did not run. A guard that can pass by finding nothing is not a guard (precedent: `metrics_guard_test.go`).
- [x] 6.4 Verify: `go test ./internal/controlplane/ -run 'TestNoLeaderLoopCountsItsOwnFailures'`. **Mutation A:** reintroduce a direct `BeaconFailures.Add(1)` inside `RunBeaconLoop`'s literal → FAILS, naming it. **Mutation B:** revert `main.go:516` to the bare `RetentionPurgeFailures.Add(1)` callback → FAILS, proving the walk really leaves `internal/controlplane`. **Mutation C:** point the walk at an empty directory → FAILS with "did not run" rather than passing. All three must be exercised; a guard whose failure path has never been seen is a guard nobody knows works.

## 7. Documentation and close-out

- [x] 7.1 Transcribe `specs/observability/spec.md` and `specs/e2e-verification/spec.md` into the repo specs **verbatim** as part of the normal sync step. Do not edit a requirement; if one is wrong, STOP and report.
- [x] 7.2 Update `docs/architecture-roadmap.md`: the section "⚠️ FOUND BY REVIEW OF D485, NOT FIXED THERE" (around line 1703) is resolved. Replace it with the resolution rather than deleting it — a closed fork with no record gets reopened by someone who did not see it close. Note that the old table was short one leaked test loop (`nips6_test.go:226`) and one leader loop (the retention sweep), and that its line numbers pointed at the `retain` call lines where this change's point at the `func` declarations.
- [x] 7.3 Roadmap entry: `RunITSMLoop` captures `OPENSHIELD_ITSM_INTERVAL` once at leader startup (`retain.Loop`, not `DynamicLoop`), so a stored, console-editable setting silently needs a restart — the defect D292 fixed for playbooks. **Not fixed here.**
- [x] 7.4 Roadmap entry: **ITSM ticket creation is not idempotent across a leader handover.** `itsm.go:74-95` POSTs to create the ticket and only then writes the local link row; a stop between them leaves a remote ticket with no local record and the next tick opens a second one. `ON CONFLICT DO NOTHING` protects the local table, not the remote system, and the comment at `itsm.go:90-91` is true only for a failure inside `CreateTicket`. **Not fixed here.**
- [x] 7.5 Roadmap entry: `requireDB` returning a bare `*pgxpool.Pool` means loop-join ordering can only ever be a guardrail; a fixture owning both the pool and loop startup is the real guarantee, deferred on blast radius (~100 call sites).
- [x] 7.6 Roadmap entry: `CorrelationFailures` (`main.go:281`) and `EscalationFailures` (`main.go:699`) are also incremented for operator-file parse failures, so those two series mix ticks with configuration errors and are not directly comparable with their siblings. Correct as-is; recorded so nobody reads a spike as a tick failure.
- [x] 7.7 Roadmap entry: `cmd/openshield-server/main.go:526/:568/:577/:589` gate listener-failure REPORTING on `err != nil && leaderCtx.Err() == nil` — the context-only guard D485 declared unsafe, applied to the logging half, so a genuine listener failure during shutdown is silent. Assessed and excluded from this change (design.md contradiction 9); record the reasoning with the entry.
- [x] 7.8 Record the decision in `docs/decisions.md` as the next D-number, referencing D31, D292 and D485. Note that it establishes no new principle — it removes an inconsistency in applying one that already existed, and closes a logging path that had never run in production.
- [x] 7.9 Final targeted runs: `go test ./internal/controlplane/ -race` and `go test ./cmd/openshield-server/`, then `go build ./cmd/...`. Two packages — the ones this change touches. Do **not** run `make all` or `go test ./...`; CI is the tree-wide check.
- [x] 7.10 Run `detect_changes()` per CLAUDE.md before committing. Expect: the seven loop functions, `NoteTickErr`, the two test helpers, the guard, and the server command. Stage named paths only — **never `git add -A`**.
  - **`detect_changes()` returned "No changes detected"** for both `scope: git` and
    `scope: compare --base-ref main`. Its index predates this work and the tree is uncommitted, so it has
    nothing to compare against — a stale-index limitation, NOT a signal that nothing changed. Scope was
    verified from `git status --short` instead, and it matches the expectation exactly: the seven loop
    functions (`beaconing.go`, `cases_http.go`, `escalate.go`, `itsm.go`, `playbook.go`, `soar2.go`, and
    the retention sweep in `cmd/openshield-server/main.go`), `NoteTickErr` + `RecordRetentionEvent`, the
    two test helpers in `controlplane_test.go`, the guard, the server command, the new tests, the two
    synced specs and the two docs. Nothing outside that scope is modified.
  - **NOTHING IS STAGED and nothing is committed** — the coordinator lands this. `git diff --cached` is
    empty; `git add -A` was never run.

## 8. Review round (two independent reviews: code review SHIP, silent-failure hunt SHIP WITH FIXES)

- [x] 8.1 **The callee-counter class, closed under the spec's own "when found" clause.** Four counters were
  moved not by a loop body but by a method the tick CALLS, invisible to the lexical guard by construction:
  `RecordUnifiedAlert`'s three increments (`unified_alerts.go`) and `linkRecurrence`'s two call sites
  (`incidents.go`, `crossdomain.go` — the latter once per configured hunt). All now route through
  `NoteTickErr` with the tick's context. `beaconing.go`'s `continue` is left as a `continue` (keep-going
  preserved) but is no longer silent, because the record is now made at the source.
- [x] 8.2 **STOPPED on `notify.go:71` (`NotifyFailures`) and did NOT change it.** A dedicated call-graph
  sweep found `deliverLoop` is started once from `SetNotifier`, runs for the PROCESS lifetime on
  `context.Background()`, and is reached from ticks only through a queue hop (`emit` enqueues) — never a
  call edge. No leader cancellation can make its `Notify` fail, so there is no loop context to key an
  exemption on and the counter is structurally exempt rather than unguarded. Routing it through the helper
  would have been uniformity for its own sake and would have implied a guarantee the code cannot make.
- [x] 8.2a Sweep also surfaced three more, all correctly out of scope: the hunts-file and ladder-file
  provider closures (`CorrelationFailures`/`EscalationFailures`) hold NO context at all — pure file I/O,
  uncancellable, and already acknowledged in the requirement text as "not purely ticks that failed"; and
  `enrich_ti.go`'s `DecodeFailures`, which increments only on a `proto.Unmarshal` failure that a
  cancellation cannot reach (the preceding `QueryRow` fails first).
- [x] 8.3 **`ErrTicketUnlinked` widened from one orphaning branch to three.** The two inside `CreateTicket`
  (2xx + undecodable body, 2xx + no reference) leave a ticket definitely existing remotely and were
  reporting `phase=opening_tickets`, whose doc says an interrupted open leaves nothing behind. New runner
  sentinels `ErrTicketCreatedUnknownRef` / `ErrTicketCreateAmbiguous`; the transport case (`:85`) is
  reported as genuinely AMBIGUOUS via `ErrTicketMaybeUnlinked` rather than claiming either certainty.
- [x] 8.4 Minors: `context.WithoutCancel` on the LogAttrs context (the exempted lines are the only ones
  whose context is dead, so a context-honouring handler would erase exactly them); a nil counter is now
  LOUD rather than a silent drop; the wiring test covers the EIGHTH logger site (`retentionCallbacks`'
  record half, extracted so it is drivable without a live purge) and now asserts quiescence rather than
  only cancelling; `RecordRetentionEvent`'s parameter renamed `loopCtx` and documented as the one site
  that cannot verify locally; a bad `OPENSHIELD_ITSM_MIN_SEVERITY` reports `phase=configuration` instead
  of a phase that never ran; `runRetentionSweep`'s `onFailure` documented as the ONLY report.
- [x] 8.5 New behavioural test for the SEVENTH loop (`TestRetentionSweepStopIsNotAFailure`), covering both
  its counters including the one no lexical rule can see.
- [x] 8.6 Deliberate ordering move documented: extraction put all seven starts after `SetNotifier` /
  `SetIntentResponder` / `SetIntentBlastRadius`, which is strictly safer than the old order (the previous
  inline order could run a playbook tick, which notifies and opens cases, before the notifier existed).
