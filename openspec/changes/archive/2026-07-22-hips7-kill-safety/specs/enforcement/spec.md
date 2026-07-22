# enforcement (delta)

## ADDED Requirements

### Requirement: The kill enforcer protects critical processes and resists pid reuse
The process-terminating enforcer MUST refuse to terminate a critical process — init, the service
manager, the remote-access daemon, the database, the container runtime, and the platform's own fleet
binaries — identified by the target's process name, in addition to refusing its own process and
init-level pids. The termination MUST target the specific process instance so that a pid recycled
between the decision and the kill is not terminated in place of the intended process; a process that
has already exited MUST be a no-op rather than an error.

#### Scenario: A kill decision spares a critical process and resists reuse
- **WHEN** a terminate decision names a critical process, and separately a non-critical process
- **THEN** the critical process is not terminated and the refusal is auditable, the non-critical process is terminated against its specific instance, and a recycled or already-exited pid is not terminated in place of another process
