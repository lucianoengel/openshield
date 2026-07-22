# execaudit-connector (delta)

## ADDED Requirements

### Requirement: The execaudit connector pairs a live record stream into events
The execaudit connector MUST provide a source that reads auditd records from a stream, pairs each
SYSCALL record with its EXECVE record by shared audit id into a process-execution event, and
delivers it to a sink. Records for different executions MUST be matched by id (not adjacency), a
malformed record MUST be dropped and counted, and the pending-pair buffer MUST be bounded so an
unbounded stream of unpaired records cannot grow memory without limit or emit a spurious event.

#### Scenario: Interleaved pairs are matched and a flood is bounded
- **WHEN** the source reads interleaved SYSCALL/EXECVE records, a malformed record, and a flood of unpaired records
- **THEN** each complete pair is emitted as a process event matched by id, the malformed record is dropped and counted, and the unpaired flood is bounded (evicted and counted) with no spurious event
