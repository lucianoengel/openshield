# Add the fail-open watchdog (T-011)

## Why

The riskiest contract in the system is unbuilt. When enforcement arrives (Phase 2) the agent
will answer fanotify permission events while a real process sits blocked in
`TASK_UNINTERRUPTIBLE` (D3). The kernel does not fail open for you: a responder that is slow,
crashes, or deadlocks hangs the process — and a machine — indefinitely. The dispatcher's
`StageDeadline` bounds the dispatcher's *wait*, but Go cannot preempt a stage goroutine, so a
pipeline that hangs still owes the kernel an answer. `pipeline.go` says so in a comment and
points here: the watchdog is a *separate* mechanism that answers the kernel regardless of what
the pipeline is doing.

D18 requires this be built and exercised for real in Phase 1 even though verdicts stay
always-allow, because the contract — not the verdict — is what is expensive to get wrong, and
USB enforcement (T-020) cannot test it (attach-time allow/deny has no blocked process, no
timeout, no race).

## What changes

**A `PermissionResponder` in the privileged agent** that, for each permission event, races the
pipeline evaluation against a hard deadline and answers the kernel with whichever resolves
first:
- **Timeout → `FAN_ALLOW`.** Fail-open is mandatory for stability (D3). A verdict that never
  arrives must not hold the process.
- **Every timeout-allow emits a HIGH-severity audit event** (D17). A silent fail-open is
  indistinguishable from a clean allow, and a rising timeout rate is the cheapest signal that
  an adversary is manufacturing bypasses by making classification slow.
- **The deadline is the watchdog's, not the pipeline's.** Even if the evaluation goroutine
  never returns, the responder has already answered and moved on; the abandoned goroutine is a
  bounded leak (also noted in `pipeline.go`), not a held kernel event.

**Self-PID bypass.** The agent's own file access (reading a policy, writing the ledger) must
never generate a permission event the agent then waits on — that is a self-deadlock. The
responder allows its own PID immediately, before any evaluation.

**Scan budgets (D17).** A per-event ceiling (wall-clock, and a hook for bytes/backtracking
budget the classifier already bounds) so one pathological file cannot consume the responder.
Exceeding the budget is a timeout-allow: audited high-severity, never a hang.

**A thin fanotify adapter at the edge.** The kernel-facing piece — reading events off the
fanotify fd and writing the `fanotify_response` struct — is a small adapter behind an
interface, so the watchdog *logic* (racing, timeout, self-PID, budgets, auditing) is tested in
ordinary Go without CAP_SYS_ADMIN. The adapter itself is exercised by the T-005 spike and by an
optional privileged integration test that skips loudly when not root.

## What this does NOT claim or cover

- **It does not enforce.** Phase 1 verdicts are always-allow (D1); the responder can carry a
  BLOCK verdict — the mechanism is complete — but nothing produces one yet. This builds the
  *contract* that makes future enforcement safe, not enforcement.
- **It does not make fail-open safe against a motivated adversary.** Fail-open IS a bypass
  (D17): anyone who can make evaluation slow gets an allow. The mitigation is that the bypass is
  loud (high-severity audit, countable rate), not that it is closed. Closing it is impossible
  without failing *closed*, which hangs the machine — the wrong trade for a data-security tool
  that must not take the host down.
- **It does not bound a stage that ignores its context.** Go cannot preempt it. The abandoned
  goroutine leaks until it returns on its own; the watchdog guarantees the *kernel* is answered,
  not that the work stops. Stated, not hidden.
- **It is not the real fanotify responder loop end to end.** The kernel adapter is thin and its
  privileged path is not run in ordinary CI. What is fully tested is the decision logic that
  makes the difference between a safe fail-open and a hung machine.

## Decisions

Depends on **D3** (fail-open from commit one: self-PID bypass, response-timeout watchdog, safe
teardown), **D17** (fail-open is a bypass; timeout-allow is audited high-severity; scan budgets),
**D18** (built and exercised in Phase 1 though verdicts stay always-allow), and **D24/D19** (the
permission window is real and tight; the watchdog is why an unbounded stall is not a language
problem).

No new decision — this implements D3/D17/D18 as written.
