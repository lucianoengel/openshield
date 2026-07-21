## Why

Phase E has the contract (D109), the detector (D110), and the enforcers (D111) — but nothing
PRODUCED exec events. This adds the observe producer: a parser for Linux auditd EXECVE +
SYSCALL records, so real process executions enter the pipeline and feed the behavioral
detector and process enforcers. It completes the HIPS path end to end (minus the privileged
audit-log I/O).

## What Changes

- `internal/connectors/execaudit`: `ParseSyscall` (pid/ppid/exe + audit id), `ParseExecve`
  (argv), `ToEvent` (combine a matched pair → a ProcessSubject Event). Whole-token field
  extraction; a mismatched pair is refused.

## Capabilities

### Added Capabilities
- `execaudit-connector`: Linux auditd exec records are parsed into process-exec events.

## Impact

- New `internal/connectors/execaudit`; `docs/decisions.md` D112.
- Proven with REAL auditd records: a SYSCALL+EXECVE pair (powershell -enc) parses to
  pid/ppid/exe and argv and combines into a PROCESS_EXEC ProcessSubject Event; the produced
  event's exec fields feed the behavioral analyzer (D110), which flags it — the full HIPS
  producer→detector path; pid is not shadowed by ppid (whole-token field match); a record
  with no exe or no audit id is rejected; a mismatched pair (different audit ids) is not
  stitched. Guards mutation-tested (whole-token-field; audit-id-mismatch; no-exe).
- NOT in scope (stated): the audit-log tail / audit-socket I/O (reading /var/log/audit or the
  netlink audit socket is privileged — a deployment concern, as with the other connectors'
  data-plane halves); the fanotify FAN_OPEN_EXEC_PERM permission producer (external-gated,
  needs root like B2 — this is the OBSERVE variant); parent_path enrichment (needs a
  process-tree lookup — left empty, a follow-up); hex-encoded argv decoding (auditd hex-
  encodes args with special chars — left as-is, still a distinct token, a follow-up). Exec
  metadata only (D10/D29); no core change (a new connector, D26).
