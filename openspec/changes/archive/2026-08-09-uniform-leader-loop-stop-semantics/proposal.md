## Why

D485 established that a leader loop's own cancellation is not a failure and must not raise that loop's
failure counter — but it applied the rule to one loop of seven. `RunCorrelationLoop` exempts a stop from
`openshield_correlation_failures_total`; `RunBeaconLoop`, `RunPlaybookLoop`, `RunEscalationLoop`,
`RunApprovalExpiryLoop`, `RunITSMLoop` and the retention sweep in `cmd/openshield-server/main.go:487` all
still count a demotion or a shutdown as a failure. Seven counters rendered side by side on one metrics
surface now mean two different things with nothing saying so, and an operator comparing them during an
incident reads the difference as signal.

Review of the first draft of this change found a second, larger problem: **the logging half has never
worked in production at all.** `cmd/openshield-server/main.go` does not import `log/slog`; every loop is
handed a literal `nil` logger, and every log call in every loop body is wrapped in `if log != nil`. So
D485's own `LOGGED EVEN WHEN NOT COUNTED` block has never emitted a line from the shipped binary, and a
requirement written against the function signature would have shipped as a no-op.

## What Changes

- **All seven leader loops adopt the D485 stop semantics.** A tick error is exempt from its failure
  counter only when the loop's own context has been cancelled AND the error IS that cancellation. Every
  other error counts exactly as today.
- **The decision moves into one shared helper, `NoteTickErr`**, which every loop calls: it always logs,
  always stamps whether the loop was stopping, and counts only when the error is not the stop. Repeating
  the guard at seven call sites is what produced this ticket; it also cannot be checked cheaply, because a
  guard verifying a hand-written conditional must reason about its polarity and about which context it
  reads.
- **The logging half is made real at both ends.** `NoteTickErr` defaults a nil logger to `slog.Default()`,
  and `cmd/openshield-server/main.go` constructs a real logger and passes it to all seven loops, with a
  wiring test asserting it. Either half alone leaves the gap open.
- **`RunApprovalExpiryLoop` gains a logger it never had.** It counts `ApprovalExpiryFailures` with no log
  line at all. **Signature change** — it takes a `*slog.Logger` like its siblings.
- **The ITSM stop log names the one interruption that leaves remote state.** Ticket creation is a remote
  POST followed by a local link row, so a stop between them leaves a ticket in someone else's queue with
  no local record and the next tick opens a second one. `SyncITSM` gains `%w` sentinels so the loop can
  actually tell that case apart — today it cannot — and the line states the actionable fact rather than a
  phase label.
- **A repo-wide guard replaces the convention:** no failure counter may be incremented inside a
  `retain.Loop`/`retain.DynamicLoop` work function anywhere in the tree. The obligation is universal but
  the check is lexical, so an increment in a method *called from* a loop is a review question rather than
  a build failure — stated in the spec rather than implied away.
- **The test helper that joins a scheduled loop becomes usable for the tests that already exist** — it
  returns an idempotent `stop()` as well as registering cleanup, because one scenario stops its loop
  mid-test deliberately.
- **Five test loops that leak against a `requireDB` pool are fixed** (`nips6_test.go:197` and `:226`,
  `soar4_test.go:584/:594/:604`). `nips6_test.go:197` runs real queries every 20ms into the next test's
  `DROP TABLE … CASCADE` plus `Migrate` — a DDL/DML collision, not merely a counter leak.

**What this change does NOT claim or cover:**

- It does **not** change what any counter means while its loop is running. No error counted today stops
  being counted except a cancellation that is the loop's own stop.
- It does **not** make a stop silent — every failing tick still produces a line.
- It does **not** claim the two config-parse increments of `CorrelationFailures` (`main.go:281`) and
  `EscalationFailures` (`main.go:699`) are ticks. They are left alone and acknowledged in the spec.
- It does **not** make interrupted ITSM ticket creation idempotent. That is recorded on the roadmap.
- It does **not** fix the context-only logging guards at `main.go:526/:568/:577/:589`, the same unsafe
  construct applied to listener reporting. Assessed, excluded with reasons, recorded.
- It does **not** touch the core pipeline, any Decision or Action shape, or the ledger.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `observability`: adds the cross-cutting rule that a scheduled leader loop's own stop is not counted by
  ANY of its counters; that the failing tick is logged regardless and that this must hold in the shipped
  process rather than only in a signature; and that the decision lives in one shared helper enforced by a
  repo-wide guard. Observability already owns what a counter means and the guard that every declared
  counter is rendered.
- `e2e-verification`: strengthens "A test stops the background work it starts" — every loop started
  against the shared database is joined, the helper supports a deliberate mid-test stop, and the ordering
  is verified by a leak test rather than asserted from a signature.

## Impact

- **Code**: `internal/controlplane/` — new `NoteTickErr`, plus `beaconing.go`, `playbook.go`,
  `escalate.go`, `cases_http.go`, `itsm.go`, `soar2.go`.
- **Commands**: `cmd/openshield-server/main.go` gains a `log/slog` import, a extracted `startLeaderLoops`
  seam and a logger passed to seven loops; the retention sweep at `:487` routes BOTH its counters through
  the helper — `RetentionPurgeFailures` and, via `RecordRetentionEvent`, `RetentionRecordFailures`.
- **API**: `(*Server).RunApprovalExpiryLoop` gains a `log *slog.Logger` parameter. Internal package; no
  external contract.
- **Tests**: `controlplane_test.go` (helpers), `nips6_test.go`, `soar4_test.go`, per-loop stop tests, the
  repo-wide guard, and a `cmd/openshield-server` wiring test.
- **Metrics**: no counter added, removed or renamed. Six counters stop moving on clean shutdown and
  leadership loss — the intended behaviour change, visible to anyone alerting on them.
- **Decisions**: depends on D31 (a gap must never be silent), D485 (the semantics being generalised),
  D292 (live-applied settings), and ADR-3/PLAT-2b. Establishes no new principle.
- **Docs**: the roadmap section recording this finding is resolved and should say so.
