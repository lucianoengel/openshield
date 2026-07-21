## Context

Content detection matches bytes; process detection analyzes execution shape. This is the
"different classifier shape" the roadmap calls E2, built as a standalone analyzer like
peer-UEBA (D53) before wiring.

## Goals / Non-Goals

**Goals:** a pure analyzer flagging LOLBin / lineage / encoded-command abuse with a score
and reasons, low-FP on routine executions.

**Non-Goals:** pipeline-stage wiring; authorable rule lists; enforcers; producer.

## Decisions

**Three orthogonal signals, combined into a score.** A LOLBin alone is not malware (many
are legitimate); a suspicious PARENT alone might be benign; an encoded command alone is
rare but not proof. The score sums the signals (LOLBin 0.35 + lineage 0.4 + encoded 0.35,
clamped to 1.0) so the strongest evidence is the CONJUNCTION — an office app spawning
encoded PowerShell — while a lone signal stays moderate. The reasons are recorded for the
audit trail.

**Low FP on routine executions.** A normal command (git, an editor launched by the desktop
shell) trips no signal and scores 0 — the same discipline as the content detectors'
false-positive corpus. The suspicious-parent list is deliberately narrow (office apps,
servers), not "any shell", to avoid flagging legitimate scripting.

**Both path separators.** A process event may carry a Windows or a Unix path; baseName
splits on both, because path.Base only handles '/' and a backslash path would otherwise read
as one long name and miss every LOLBin.

## Risks / Trade-offs

- **Heuristic, tunable.** The lists and weights are a strong starter; real tuning needs
  process telemetry (T-015), and an admin-authorable list (like D100) is the general answer.
- **Evidence, not a verdict.** The analyzer scores; the policy decides. A high score does not
  auto-kill — the closed action set and the enforcers (D111) gate that.
