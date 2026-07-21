## Context

D109 added the verbs; enforcers carry them out. The flow enforcer (D73) is the template: a
TargetedEnforcer acting on a caller-supplied target, with dangerous actuation behind a seam
the owning handler applies.

## Goals / Non-Goals

**Goals:** a kill enforcer (fail-safe) and a deny enforcer (seam-based), on the existing
interface.

**Non-Goals:** engine dispatch wiring; the real exec-permission handler; process-tree kill.

## Decisions

**Fail-SAFE, like the watchdog fails open.** KILL_PROCESS is the most destructive verb, so
the enforcer refuses the targets that would be catastrophic: pid ≤ 1 (the kernel and init)
and its OWN pid, plus a non-numeric target. A process-killer must never fire on an
unparseable or system-critical target — the guards run BEFORE any kill.

**DENY_EXEC records, the handler applies.** The deny enforcer does not itself answer a
kernel exec-permission event (it does not own that fd); it records a deny on an
ExecController the permission handler exposes — the flow-enforcer pattern, so the enforcer
never races the handler for a resource it does not own. A deny with no controller is an
error, because a deny that goes nowhere silently ALLOWS the execution (D17).

**Per-OS kill, portable enforcer.** The safety logic is portable; only `platformKill` is
per-OS (syscall.Kill on Unix, a stub elsewhere) so the package builds on the CI matrix while
actuating only where supported (Linux-first, D8).

## Risks / Trade-offs

- **Only the target pid, not its tree.** A malicious process may have already forked; killing
  the tree (or the session) is a follow-up. The single-pid kill is the honest first step.
- **A pid can be reused** between decision and kill (a TOCTOU). The window is small and the
  fanotify/exec producer will carry a more stable handle; noted, mirroring the file
  enforcers' O_NOFOLLOW discipline (D65).
