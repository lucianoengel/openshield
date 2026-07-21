## Why

Phase E's contract (D109) defined DENY_EXEC and KILL_PROCESS; this builds the enforcers that
carry them out — the process domain implementing the EXISTING TargetedEnforcer, the third
after files and flows. Process control is powerful and dangerous, so the kill enforcer
carries the fail-safe discipline the capability demands.

## What Changes

- `internal/enforcers/process`: `KillEnforcer` (KILL_PROCESS — terminates a process by pid,
  fail-safe) and `DenyEnforcer` (DENY_EXEC — records a deny on an `ExecController` seam the
  permission handler applies, the flow-enforcer pattern). Per-OS `platformKill`
  (linux/darwin syscall.Kill; a stub elsewhere for the CI matrix).

## Capabilities

### Modified Capabilities
- `enforcement`: adds the process-control enforcers (kill / deny-exec).

## Impact

- New `internal/enforcers/process`; `docs/decisions.md` D111.
- Proven: KILL_PROCESS terminates a REAL spawned process (rootless) — the sleep is SIGKILLed,
  not exited cleanly; the enforcer REFUSES pid ≤ 1 (kernel/init), its own pid, and a
  non-numeric/empty target (a killer firing on a bad target is catastrophic); DENY_EXEC
  records the deny on the controller, and a missing controller or empty target errors (a
  deny that goes nowhere silently ALLOWS). Guards mutation-tested (pid≤1; self-pid;
  nil-controller — removing the pid≤1/self guards literally killed the test runner,
  confirming they matter).
- NOT in scope (stated): wiring the enforcers into an engine that dispatches process
  Decisions (the engine registers enforcers per action, D49 — a follow-up); the real
  fanotify FAN_OPEN_EXEC_PERM handler that DENY_EXEC's ExecController fronts (external-gated,
  needs root like B2); process TREE kill (only the target pid, not descendants — a follow-up).
  Reuses the existing TargetedEnforcer interface unchanged (target = pid / exec handle),
  Decision carries only the verdict (D14/D39).
