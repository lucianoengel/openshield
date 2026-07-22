# Design — exec producer source

## Pair by audit id, bounded

auditd emits an exec as a SYSCALL record immediately followed by an EXECVE record sharing one audit
id. The Scanner buffers a partial pair per id and emits the combined Event when both halves arrive —
robust to interleaving (records for different execs matched by id, not adjacency). A malformed
record (no exe, no id) is dropped and counted. The pending buffer is bounded by a FIFO of ids: past
the cap the oldest unpaired record is evicted and counted, so a stream of half-pairs (only SYSCALLs,
never EXECVEs — a malformed or hostile feed) cannot grow memory without limit and never emits a
spurious event.

## A stream, not a specific transport

Reading auditd is a deployment choice — a tailed `/var/log/audit/audit.log`, an audit fifo, or the
netlink socket. The Scanner and the engine source read from a generic stream, so the transport is
configuration (`OPENSHIELD_EXEC_AUDIT_LOG`), not baked in. Following semantics (a blocking fifo/
socket that streams appends) come from the source; a plain file reads to EOF, which is fine for a
one-shot and the operator points it at a following stream in production.

## Proven

The Scanner test feeds a fixture with interleaved pairs, a malformed record, and asserts three
correctly-assembled events (matched by pid/exe/args) plus a non-zero drop count; a 20k unpaired-
SYSCALL flood emits zero events and is evicted/counted (the bound). The engine-source test feeds a
fixture stream and asserts a ProcessSubject event lands on the pipeline channel — the connector is
wired.
