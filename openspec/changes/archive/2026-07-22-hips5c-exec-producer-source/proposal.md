# HIPS-5c: exec producer source (auditd → execaudit → pipeline)

## Why

The execaudit parsers (`ParseSyscall`/`ParseExecve`/`ToEvent`) were built and tested, but nothing
read a live auditd stream and PAIRED the SYSCALL+EXECVE records into Events — so no process
execution ever entered the pipeline. HIPS-5a made KILL runnable and HIPS-5b made detection reach a
decision; this is the missing PRODUCER that completes Phase E end to end.

## What Changes

- **`execaudit.Scanner`**: reads auditd records from a stream, pairs each SYSCALL with its EXECVE by
  audit id, and delivers the combined ProcessSubject Event to a sink. A malformed record is dropped
  and counted (D17/D28); the pending-pair buffer is BOUNDED (a flood of unpaired records is evicted,
  not accumulated) so attacker-influenced audit input cannot grow memory without limit.
- **The engine gains an exec source** (`OPENSHIELD_EXEC_AUDIT_LOG`): it reads the configured stream,
  pairs records, and feeds process events into the SAME pipeline as file/DNS events — additive,
  observe-only by default (a KILL requires a KILL policy + `OPENSHIELD_ENFORCE`).

This modifies the `execaudit-connector` and `endpoint-engine` capabilities. No core change; it is a
producer, like the DNS source.

## Impact

- Affected specs: `execaudit-connector`, `endpoint-engine`
- Affected code: `internal/connectors/execaudit/source.go` (Scanner), `cmd/openshield-engine`
  (execSource + wiring).
- Not in scope (stated): the choice of auditd transport (tailed log vs fifo vs netlink socket — a
  deployment concern; the source reads a stream); continuous follow across log rotation (the stream
  is expected to be a following source); parent_path enrichment via a process-tree lookup (noted in
  ToEvent as a follow-up); the detectors' evasions (HIPS-6).
