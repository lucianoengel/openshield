# endpoint-engine (delta)

## ADDED Requirements

### Requirement: The engine runs an optional exec source into the pipeline
The engine MUST be able to run the auditd exec connector as an additional event source, enabled by
configuration. When enabled, it MUST read the configured record stream, pair the records into
process-execution events, and feed them into the same pipeline as file events, so process executions
are classified/decided/audited. The exec source MUST be additive to file watching and observe-only
by default (it produces events; containment requires an enforcement opt-in), and its producer MUST
be tracked so the event stream is not closed while it is running.

#### Scenario: A process execution flows through the pipeline
- **WHEN** the engine has the exec source enabled and reads a paired SYSCALL/EXECVE record set
- **THEN** a process-execution event is produced onto the engine's event stream for the pipeline to process, and the source shuts down cleanly with the engine
