# enforcement (delta)

## ADDED Requirements

### Requirement: The engine selects the enforcement target by event kind
The engine MUST supply an enforcer the target appropriate to the event's kind: the process id for a
process event (so a process-terminating enforcer can act) and the resolved path for a file event.
A process-terminating enforcer MUST be registrable under the enforcement opt-in, and when a decision
is to terminate a process, the engine MUST carry it out against the event's process id, refusing to
terminate itself or an init-level process, and auditing a refused or failed termination.

#### Scenario: A kill decision terminates the named process and never the engine
- **WHEN** the engine processes a process event with a terminate decision, and separately a process event naming the engine's own process
- **THEN** the named process is terminated while the engine refuses to terminate itself, and both the termination and the refusal are audited
