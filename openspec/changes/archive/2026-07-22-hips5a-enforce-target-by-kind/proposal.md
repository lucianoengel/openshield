# HIPS-5a: enforce target-selection by event kind + register KILL_PROCESS

## Why

Phase E landed the contract, the behavioral detectors, and the process enforcers, but HIPS is not
runnable: `engine.enforce` supplies `ev.GetFilesystem().GetResolvedPath()` as the target for EVERY
enforcer, and a process event has no filesystem — so a pid-based enforcer receives `""`, fails to
parse it, and SELF-REFUSES. And `registerEnforcers` never adds the process enforcers, so even a
KILL_PROCESS decision reaches no enforcer. HIPS containment could never act.

## What Changes

- **Target-selection by event KIND**: `enforceTarget(ev)` returns the process PID for a process
  event (KILL_PROCESS / DENY_EXEC) and the resolved path for a file event (quarantine / encrypt).
  So a pid-based enforcer now receives the pid, not an empty path.
- **Register `KillEnforcer`** under `OPENSHIELD_ENFORCE` (observe-only default preserved): a
  KILL_PROCESS decision now terminates the process, POST-exec containment.
- **DENY_EXEC is explicitly deferred**: true inline exec-block needs an exec-permission handler
  (`FAN_OPEN_EXEC_PERM`), which is privileged and env-gated like the inline file responder (B2);
  there is no `ExecController` to wire until that lands, so the deny enforcer is not registered.

## Impact

- Affected specs: `enforcement`
- Affected code: `internal/engine/engine.go` (enforceTarget + enforce), `cmd/openshield-engine`
  (register KillEnforcer).
- Not in scope (stated): the exec-event PRODUCER source (auditd tail → execaudit → Event, the next
  HIPS-5 unit); wiring behavioral detection to a decision (the detectors are unwired — a following
  unit); DENY_EXEC inline (needs FAN_OPEN_EXEC_PERM); KILL safety hardening beyond self+pid≤1
  (HIPS-7: critical-process allowlist, pid-reuse revalidation).
