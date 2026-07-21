## Why

Phase E's exec contract (D109) lets a process event flow the pipeline, but nothing yet
DETECTS process abuse. This adds the behavioral detection domain (E2) — a different
classifier shape than content patterns: it analyzes the SHAPE of an execution (binary,
lineage, arguments) to flag LOLBin abuse, suspicious parent→child lineage, and encoded /
download-and-execute command lines.

## What Changes

- `internal/behavioral.Analyze(execPath, parentPath, args) Finding` — a pure, deterministic
  analyzer over exec METADATA (D10/D29). `Finding{LOLBin, SuspiciousLineage, EncodedCommand,
  Score, Reasons}`. `baseName` handles both path separators (Windows + Unix).

## Capabilities

### Added Capabilities
- `behavioral-detection`: a process-behavior analyzer scoring LOLBin / lineage / encoded-command abuse.

## Impact

- New `internal/behavioral`; `docs/decisions.md` D110.
- Proven: an office app spawning encoded PowerShell scores ≥0.9 (LOLBin + lineage +
  encoded — the malware hallmark); a webserver spawning a shell (webshell) and a
  curl-piped-to-bash cradle are flagged; a routine command (git status, a text editor)
  scores 0 (FP discipline); the score clamps at 1.0 and records its reasons; a Windows
  backslash path resolves to its binary name. Guards mutation-tested (LOLBin; lineage;
  encoded-command; backslash-path-handling).
- NOT in scope (stated): wiring the analyzer into a behavioral pipeline STAGE that exposes
  the Finding to the policy (the policy already sees the raw exec fields via D109's
  buildInput; a richer Finding-in-context is a follow-up); an admin-authorable LOLBin /
  lineage rule list (like D100's signed custom rules, a follow-up); the process ENFORCERS
  (D111) and PRODUCER (D112). Evidence for a policy, not a verdict — the policy (closed
  action set) decides DENY_EXEC/KILL_PROCESS/ALERT.
