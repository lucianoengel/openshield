## Context

Files and flows are established event domains. HIPS adds a third — processes — and, unlike
prior phases, it EXPANDS the closed action set. That expansion is the T1 decision the owner
approved; doing it contract-first proves the fit before committing to producers/enforcers.

## Goals / Non-Goals

**Goals:** a process-exec Event shape + two process-control verbs, proven to fit the
unchanged core, with the closed-set discipline intact.

**Non-Goals:** the classifier, enforcers, or producer (later increments).

## Decisions

**Widen the closed set deliberately, in every guard.** DENY_EXEC and KILL_PROCESS are added
to the proto AND to validate.go's knownActions AND to policy's actionNames AND to the pinned
action-enum test — four deliberate edits, because the whole point of the closed set (D14) is
that adding a verb is a decision made in code, not a proto value that silently becomes
valid. A compromised control plane still cannot express a free-form command; it can only
select one of the finite, enforcer-backed verbs.

**Two distinct verbs, not one.** DENY_EXEC (refuse an execution — the exec-time analogue of
BLOCK) and KILL_PROCESS (terminate a running process) are different actions with different
enforcers and different failure modes; collapsing them would lose that distinction. Each
gets its own capability and guard.

**ProcessSubject is metadata only.** pid/ppid/exec_path/args/parent_path — enough for
LOLBin and lineage rules — but never process memory or file content (D10/D29). pid is the
enforcement target (the process analogue of a file path / flow_id), carried in the Event,
not the Decision (D39).

## Risks / Trade-offs

- **Process control is powerful and dangerous.** A wrong KILL_PROCESS can take down a
  legitimate process; the enforcers (D111) will need the same fail-safe discipline as the
  fail-open watchdog. The contract makes the capability explicit and auditable first.
- **args are metadata but can be sensitive** (a command line may contain a secret). They are
  local-policy input; telemetry redaction of args is a follow-up consideration for D112.
