## 1. The watchdog logic (no kernel)

- [x] 1.1 `internal/agent/watchdog` package: `PermissionEvent`, `Responder` interface
      (`Allow`/`Deny`), `Evaluator` interface (evaluate an event → verdict), `Watchdog` holding
      selfPID, per-event budget, and an audit callback
- [x] 1.2 `Handle(ctx, event)`: self-PID → Allow immediately (no eval); else race eval against the
      budget deadline; deadline first → Allow + high-severity audit; result first → answer per
      verdict. Exactly one answer per event
- [x] 1.3 Discard a late evaluation result after a timeout has answered

## 2. Auditing the fail-open

- [x] 2.1 The high-severity fail-open event uses the `core.Severity`/outcome vocabulary and goes
      through an audit callback that appends to the ledger AFTER the kernel is answered
- [x] 2.2 A failed audit append surfaces (never silent) but does not retract the allow already
      written

## 3. Tests — the contract

- [x] 3.1 **Test**: a slow evaluator yields FAN_ALLOW within the deadline. `TestSlowEvalFailsOpenInTime`
- [x] 3.2 **Test**: exactly one answer per event even when the result lands after the timeout.
      `TestNoDoubleAnswer`
- [x] 3.3 **Test**: a fail-open emits a HIGH-severity, distinguishable audit event.
      `TestFailOpenIsAuditedHighSeverity`
- [x] 3.4 **Test**: self-PID is allowed without the evaluator ever being called.
      `TestSelfPIDBypassesEvaluation`
- [x] 3.5 **Test**: a "bomb" (slow) evaluation hits the budget rather than hanging, and is
      audited. `TestBudgetCeilingNotHang`
- [x] 3.6 **Test**: a failed audit append surfaces but the allow still happened.
      `TestAuditFailureDoesNotRetractAllow`

## 4. The kernel adapter (thin, edge)

- [x] 4.1 A `Responder` implementation that writes a `fanotify_response` to the fanotify fd
      (mirrors the spike's `resp[0:4]=fd, resp[4:8]=FAN_ALLOW`)
- [x] 4.2 An optional privileged integration test that sets up a real FAN_OPEN_PERM mark, triggers
      an open, and asserts the watchdog answers — skipped LOUDLY when not root / no fanotify
- [x] 4.3 The adapter is small and isolated; the decision logic in §1–3 is what CI proves

## 5. Docs

- [x] 5.1 Note in `docs/decisions.md` (under D3/D17/D18, no new number needed unless one emerges)
      that the watchdog is built and the fanotify answer path is its own mechanism, separate from
      the dispatcher deadline
- [x] 5.2 Mark T-011 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| timeout answers Deny instead of Allow | `TestSlowEvalFailsOpenInTime`, `TestBudgetCeilingNotHang` |
| self-PID check dropped | `TestSelfPIDBypassesEvaluation` |
| fail-open severity downgraded to info | `TestFailOpenIsAuditedHighSeverity` |
| a late result answers twice | `TestNoDoubleAnswer` (buffered channel + single-answer assertion) |

All watchdog logic tests pass under `-race`. The kernel edge
(`FanotifyResponder`) is a thin adapter; the privileged integration test
`TestFanotifyPermissionAnsweredForReal` sets up a real `FAN_OPEN_PERM` mark and
answers a blocking open when run as root, and SKIPS LOUDLY otherwise (confirmed:
"LOUD SKIP: fanotify permission mode unavailable" without CAP_SYS_ADMIN). The
split is deliberate — what CI without privilege proves is the decision logic that
separates a safe fail-open from a hung host; the fd write is spike-proven and
one `unix.Write`.
