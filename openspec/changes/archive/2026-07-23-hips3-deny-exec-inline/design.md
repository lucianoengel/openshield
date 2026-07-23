## Context

The watchdog (T-011) owns the fanotify permission answer under a hard budget with fail-open, and already
routes `VerdictBlock → Responder.Deny(e)` ("complete for Phase 2"). `engine.Process` returns a
`*corev1.Decision`. `ACTION_DENY_EXEC` is in the closed set; the `DenyEnforcer` + `ExecController` seam
exist but are unregistered ("no ExecController to wire until that lands"). T1 sign-off unblocks the
action-set use.

## Goals / Non-Goals

**Goals:**
- Map an exec-permission event to `VerdictBlock` iff the pipeline decides `DENY_EXEC`, so a bad exec is
  refused inline — reusing the watchdog's existing fail-open machinery.
- Keep the decision logic testable WITHOUT root (the fanotify syscall is a thin adapter behind Responder).
- Register the DenyEnforcer now that the inline path exists.

**Non-Goals:**
- The `FAN_OPEN_EXEC_PERM` mark/read/respond syscalls — root/CAP_SYS_ADMIN + a real fanotify mount,
  Linux-gated exactly like NIPS-1 TPROXY and the file responder B2. This increment builds the logic; the
  privileged producer is the adapter that feeds it (noted, deferred).
- Changing the closed action set or the watchdog's fail-open contract.

## Decisions

1. **`ExecEvaluator` wraps an abstract `ExecDecider`, not the engine.** `ExecDecider func(ctx,
   PermissionEvent) (corev1.Action, error)` — the watchdog package stays engine-free (no import cycle),
   and the evaluator is pure/testable. `Evaluate` returns `VerdictBlock` iff the action is
   `ACTION_DENY_EXEC`; every other action (ALLOW, ALERT, …) is `VerdictAllow` — inline-DENY is the ONLY
   verdict that blocks an exec, so a mis-decision degrades to allow (fail-safe for availability, D17), and
   a decider ERROR propagates so the WATCHDOG fail-opens (never hang an exec on a crash).

2. **Production decider = engine.Process.** In `cmd/openshield-engine`, the decider builds an
   `EVENT_KIND_PROCESS_EXEC` event (the binary path → `ProcessSubject`, the pid) and runs `engine.Process`,
   returning `decision.Action`. The engine's own StageDeadline bounds it, and the watchdog's budget is the
   backstop — two independent bounds, as designed (a hung stage still owes the kernel an answer).

3. **Fail-open is the watchdog's, unchanged.** Block ONLY on an explicit `DENY_EXEC` verdict; timeout or
   error → the watchdog answers `Allow` and audits high-severity. Inline PREVENTION never becomes inline
   DENIAL-OF-SERVICE — the riskiest-contract discipline (D18) is preserved by delegating to the watchdog.

4. **Do NOT register the DenyEnforcer in the inline path — it would double-apply.** The watchdog's
   `ExecEvaluator` calls `engine.Process` synchronously, and `engine.Process` runs its `enforce()` loop
   internally. If a `DenyEnforcer` were registered, a `DENY_EXEC` decision would fire the enforcer AND the
   watchdog's `Responder.Deny` — two denies for one exec. In the inline model the watchdog's kernel answer
   IS the enforcement, so no engine enforcer is needed. `DenyEnforcer` + `ExecController` remain built for
   the ALTERNATE async flow-enforcer model (an engine that dispatches exec events without holding the
   permission fd); the stale "no ExecController to wire" comment in `registerEnforcers` is replaced with
   this resolved rationale. (Original plan was to register it; building the inline path revealed the
   double-apply, so the honest call is to leave it unregistered.)

## Risks / Trade-offs

- **The privileged producer is not in this increment.** Honest scope: the decision→deny logic + fail-open
  are built and tested; the `FAN_OPEN_EXEC_PERM` syscall adapter (root-gated, needs a real mount) is the
  remaining wiring, exactly the gating NIPS-1 and the file responder carry. The T1-gated LOGIC is real and
  covered.
- **Only DENY_EXEC blocks.** Deliberate: a mis-decision allows (availability over a false block), and the
  watchdog fail-opens on any error/timeout — an exec is never hung by this path.
