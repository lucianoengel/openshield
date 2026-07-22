# HIPS-5b: wire behavioral detection to a decision

## Why

The behavioral detectors (`behavioral.Analyze` — LOLBin abuse, suspicious parent→child lineage,
encoded/download-and-execute command lines) were committed for Phase E but had **zero callers**: no
process event ever produced a behavioral verdict, so HIPS detection could not reach a decision.
HIPS-5a made KILL runnable *given* a decision; this produces the decision.

## What Changes

- **`buildInput` runs `behavioral.Analyze` for a process event** and exposes its verdict as a typed
  policy input (`event.behavioral = {score, lolbin, suspicious_lineage, encoded_command}`). It runs
  in the ENGINE on process METADATA only — pure and content-free, so it needs no sandboxed worker
  (D29 governs content parsing, not metadata). The POLICY decides the action, never the detector
  (T1).
- **The default policy ALERTs on a suspicious behavioral score** (`≥ 0.5`). Observe-safe: the
  shipped default ALERTs, it does NOT KILL — an operator raises to KILL_PROCESS deliberately. File
  and network events have no `event.behavioral`, so the rule never fires on them. The ALERT/ALLOW
  rules are restructured around a single `alert` flag so the two alert conditions (PII, behavioral)
  compose without a conflicting `decision`.

This modifies the `policy-evaluation` capability. No core change; behavioral fits as a metadata
analysis feeding the existing policy-input seam.

## Impact

- Affected specs: `policy-evaluation`
- Affected code: `internal/policy/mapping.go` (buildInput enrichment), `internal/policy/default.rego`.
- Not in scope (stated): the exec PRODUCER source that generates process events (HIPS-5c —
  auditd tail); the behavioral detectors' own evasions (HIPS-6 — 1-char bypasses); a KILL-by-default
  posture (deliberately ALERT; KILL is an operator policy choice, T1); behavioral as its own
  detector-type in the classification (kept as a policy input, simpler and decoupled from PII).
