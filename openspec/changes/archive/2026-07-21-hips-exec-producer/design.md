## Context

The behavioral detector (D110) and enforcers (D111) need exec events. auditd is the standard
Linux exec-event source and is a pure text format — parseable and testable without the
privileged log I/O.

## Goals / Non-Goals

**Goals:** parse an auditd EXECVE+SYSCALL pair into a ProcessSubject Event; feed the detector.

**Non-Goals:** the audit-log I/O; the fanotify permission producer; parent-path enrichment.

## Decisions

**Two records, linked by audit id.** An exec is a SYSCALL record (pid/ppid/exe) plus an
EXECVE record (argv), sharing an audit event id. ToEvent REQUIRES the ids to match —
stitching an argv onto the wrong process would misattribute the execution, so a mismatch is
an error, not a guess.

**Whole-token field extraction.** Audit records are "key=value key=value"; naive substring
matching would let "pid" match inside "ppid". The field reader requires the key to start at
a boundary (start or after a space), so pid and ppid are read correctly — the test asserts
exactly this (pid must not be shadowed by ppid).

**Observe, not permission.** This is the OBSERVE producer (auditd records an exec that
already happened); the PERMISSION producer (FAN_OPEN_EXEC_PERM, which can DENY before exec)
needs init-namespace CAP_SYS_ADMIN and is external-gated like B2. The observe path feeds
detection + post-exec KILL_PROCESS; inline DENY_EXEC awaits the privileged handler.

## Risks / Trade-offs

- **Post-exec, not pre-exec.** auditd sees an exec after it ran, so it enables detection and
  KILL, not inline DENY. The permission producer is the inline-prevention half, external-
  gated. Honest: observe first.
- **parent_path is empty** until a process-tree resolver fills it; the behavioral lineage
  rules that need it degrade gracefully (they simply do not fire on parent) rather than error.
