# Design — enforce target by kind

## One target selector, by event kind

The enforcer target is intrinsically kind-specific: a file enforcer acts on a path, a process
enforcer on a pid. The old code hard-coded the filesystem path, which is empty for a process event
— so the pid enforcer's own fail-safe (reject a non-pid target) fired on every process event, and
containment was impossible. `enforceTarget(ev)` selects by kind: `GetProcess() != nil` → the pid as
a string; otherwise the resolved filesystem path. Additive and total — a future kind that needs a
different target extends this one function.

## KILL is runnable; DENY_EXEC is honestly deferred

KILL_PROCESS is post-exec containment: it needs only the pid, which the event carries, so it runs
now. DENY_EXEC is true inline prevention — it must answer a kernel exec-permission event before the
process runs, which requires `FAN_OPEN_EXEC_PERM` (privileged, env-gated like B2) and an
`ExecController` to record the deny. None of that exists yet, so registering a deny enforcer would
be dead code. It is deferred with a comment, not faked.

## Real-adversary proof

The test spawns a REAL `sleep` child, processes a process event naming its pid with a KILL policy
and a registered KillEnforcer, and asserts the child is actually reaped — not a mock of the kill.
The mutation reverting `enforceTarget` to the filesystem path leaves the child alive, so the fix is
proven load-bearing. Self-protection is also exercised: a KILL targeting the engine's own pid is
refused and the failure is audited (we are still running to assert it).
