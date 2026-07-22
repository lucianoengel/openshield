# execaudit-connector Specification

## Purpose
The process-exec producer: a parser for Linux auditd SYSCALL and EXECVE records that combines a matched pair into a process-exec Event (pid, ppid, executable, argv), so process executions enter the same pipeline as file, network, and log events and feed the behavioral detector and process enforcers. It is a pure parser; the audit-log tail / audit-socket I/O and the privileged fanotify permission producer are separate, external-gated concerns.

## Requirements

### Requirement: The exec producer parses auditd records into process-exec events
The producer MUST parse a Linux auditd SYSCALL record into the pid, parent pid, executable,
and audit event id, and an EXECVE record into the argument vector, extracting fields by whole
token so that pid is not confused with ppid. It MUST combine a SYSCALL and EXECVE pair into a
process-exec event only when they share an audit event id, refusing a mismatched pair, a
record with no executable, or a record with no audit id — never producing a misattributed or
partial event.

#### Scenario: A matched record pair produces a process-exec event
- **WHEN** the producer parses a SYSCALL and EXECVE pair with the same audit id
- **THEN** it produces a process-exec event with the pid, executable, and argv, while a mismatched pair or a record missing its exe or id is rejected
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
## ADDED Requirements

### Requirement: The execaudit connector decodes auditd's value encodings
The execaudit connector MUST decode the value encodings auditd uses for argv and exe fields: a
double-quoted value is unquoted, and a bare hex-encoded value (auditd's form for a value containing
a space or special character) is hex-decoded, so a command whose argument contains a space reaches
detection as its real text rather than an opaque hex blob. A quoted value MUST NOT be hex-decoded.

#### Scenario: A hex-encoded argv value is decoded to its real text
- **WHEN** the connector parses an EXECVE record whose spaced argument auditd hex-encoded, and a quoted simple value
- **THEN** the hex-encoded argument is decoded to its original text while the quoted value is only unquoted
