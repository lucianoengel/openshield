## MODIFIED Requirements

### Requirement: The exec producer parses auditd records into process-exec events
The producer MUST parse a Linux auditd SYSCALL record into the pid, parent pid, executable,
and audit event id, and an EXECVE record into the argument vector, extracting fields by whole
token so that pid is not confused with ppid. It MUST combine a SYSCALL and EXECVE pair into a
process-exec event only when they share an audit event id, refusing a mismatched pair, a
record with no executable, or a record with no audit id — never producing a misattributed or
partial event. The producer MUST also capture the process's start-time at observation and carry it
on the event when it can be read, so a later enforcement can distinguish the observed process instance
from a recycled pid; when the start-time cannot be read (the process already exited), the event MUST
still be produced, with the start-time absent, rather than dropped.

#### Scenario: A matched record pair produces a process-exec event
- **WHEN** the producer parses a SYSCALL and EXECVE pair with the same audit id
- **THEN** it produces a process-exec event with the pid, executable, and argv, while a mismatched pair or a record missing its exe or id is rejected

#### Scenario: The event carries the observed process's start-time when available
- **WHEN** the producer emits a process-exec event for a live process
- **THEN** the event carries the process's start-time captured at observation; and when the start-time cannot be read the event is still emitted with the start-time absent
