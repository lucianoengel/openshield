## Why

HIPS containment can KILL a process POST-exec (HIPS-5), but true INLINE prevention — refusing an exec
BEFORE it runs — was gated on T1 (the closed-action-set expansion, D14) and an exec-permission handler.
The owner has now given **T1 sign-off** for `DENY_EXEC`. `ACTION_DENY_EXEC` already exists in the closed
enum, the `DenyEnforcer` is built, and the watchdog already supports `VerdictBlock → Responder.Deny`
under a hard fail-open budget. The missing piece is the DECISION→VERDICT mapping: an exec-permission
event must run through the pipeline and, iff the decision is `DENY_EXEC`, be answered `FAN_DENY` — a
malicious binary blocked at exec, not killed after it has already run.

## What Changes

- **`ExecEvaluator`** (`internal/agent/watchdog`): a `watchdog.Evaluator` that runs an injected exec
  decider on a permission event and returns `VerdictBlock` iff the decision is `ACTION_DENY_EXEC`, else
  `VerdictAllow`. A decider error propagates so the watchdog FAIL-OPENS (never hangs an exec). The
  decider is an abstract func (no engine import — no cycle); production backs it with `engine.Process`.
- **Engine-backed production decider** (`internal/agent/execguard`): `Decider(engine)` builds an
  `EVENT_KIND_PROCESS_EXEC` event from the permission event, runs `engine.Process`, and returns the
  decision's action for the `ExecEvaluator` (in its own package so it can import the engine without a
  watchdog↔engine cycle). The `DenyEnforcer` is deliberately left UNREGISTERED: `engine.Process` runs its
  own `enforce()` loop, so registering it would DOUBLE the deny (enforcer + watchdog answer). The stale
  "no ExecController to wire" comment is replaced with the resolved rationale.
- The actual `FAN_OPEN_EXEC_PERM` fanotify mark + read/respond syscalls are the ROOT-gated Linux adapter
  behind the watchdog's `Responder` (like the file responder B2 / NIPS-1 TPROXY) — the decision logic and
  fail-open are built and tested WITHOUT privilege.

## Capabilities

### New Capabilities
<!-- none: completes the existing inline-prevention capability's exec path. -->

### Modified Capabilities
- `inline-prevention`: a `DENY_EXEC` decision now inline-blocks an exec (answered `FAN_DENY`), under the
  watchdog's hard fail-open budget.

## Impact

- `internal/agent/watchdog`: `ExecEvaluator` + `ExecDecider` type.
- `internal/agent/execguard`: the engine-backed `Decider` adapter (new package, no import cycle).
- `cmd/openshield-engine`: resolved comment — `DenyEnforcer` stays unregistered (would double-apply).
- No proto/core change (the action + enforcer exist), no new dependency. The `FAN_OPEN_EXEC_PERM`
  producer/responder is the root-gated adapter (deferred, noted).
