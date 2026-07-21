## Why

Phase E (HIPS) makes the XDR bet the owner approved: the endpoint gains PROCESS CONTROL. The
foundation is the contract — a process-exec Event shape and the DELIBERATE expansion of the
closed action set (T1, D14) with two new typed verbs. Contract-first (as D69 did for
network), proven to fit the unchanged core before any producer or enforcer is built.

## What Changes

- Proto: `ProcessSubject` (pid, ppid, exec_path, args, parent_path — exec METADATA only),
  `EVENT_KIND_PROCESS_EXEC`, Event target variant `process`; two new actions
  `ACTION_DENY_EXEC` and `ACTION_KILL_PROCESS`.
- The closed-set maps (validate.go knownActions, policy actionNames) + the pinned
  action-enum test gain the two verbs — the deliberate edits the T1 guard forces.
- `policy.buildInput` exposes `input.event.{exec_path, parent_path, args}` for a behavioral
  policy.

## Capabilities

### Modified Capabilities
- `decision-contract`: the closed action set is widened with two process-control verbs.

## Impact

- `proto/…/{event,decision}.proto` (regenerated); `internal/core/validate.go`,
  `internal/policy/mapping.go`, `internal/core/schema_test.go`; `docs/decisions.md` D109.
- Proven (the D69/D53 fitness pattern): a process-exec Event flows through the UNCHANGED
  core.Dispatcher → a behavioral policy (LOLBin spawned by an office app) → a KILL_PROCESS
  decision → audited via the existing OnOutcome sink → carried out by the EXISTING
  TargetedEnforcer via target = pid. Dispatcher/State/Stage/Registry/Enforcer-interface/
  OnOutcome/ledger ALL untouched; ProcessSubject carries no memory/content field; both verbs
  validate under the closed set. The action-enum-closed and action-count tests were updated
  DELIBERATELY (the T1 guard working as designed).
- NOT in scope (this increment): the behavioral CLASSIFIER (LOLBin/lineage detectors, D110);
  the process ENFORCERS (kill/deny, D111); the exec PRODUCER (auditd/eBPF/fanotify-exec,
  D112 — the FAN_OPEN_EXEC_PERM permission variant is external-gated like B2). This is the
  contract + fitness proof only. The action vocabulary stays CLOSED (D14) — widened by
  explicit decision, never opened to a free-form command.
