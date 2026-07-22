## MODIFIED Requirements

### Requirement: The kill enforcer protects critical processes and resists pid reuse
The process-terminating enforcer MUST refuse to terminate a critical process — init, the service
manager, the remote-access daemon, the database, the container runtime, and the platform's own fleet
binaries — identified by a TRUSTED identity that the target cannot forge: the process's real
executable (not a self-settable process name), protected only when that executable is owned by root
and not writable by non-owners. A process that merely renames itself (its `comm`/`argv[0]`) to a
critical name MUST still be terminable — the protection MUST NOT be grantable by self-naming. The
enforcer MUST also refuse its own process and init-level pids. The termination MUST target the
specific process instance identified at OBSERVATION: the enforcer MUST revalidate the target's
captured identity (its process start-time, captured when the event was produced) against the current
holder of the pid at kill time, and MUST NOT terminate a pid whose current start-time does not match —
so a pid recycled between the decision and the kill spares the new holder. A process that has already
exited MUST be a no-op rather than an error. When no captured identity is available, the enforcer acts
best-effort on the pid without a false claim of revalidation.

#### Scenario: A kill decision spares a critical process and resists reuse
- **WHEN** a terminate decision names a critical process, and separately a non-critical process
- **THEN** the critical process is not terminated and the refusal is auditable, the non-critical process is terminated against its specific instance, and a recycled or already-exited pid is not terminated in place of another process

#### Scenario: A self-renamed process does not gain immunity
- **WHEN** a non-critical process sets its name to a critical one (e.g. `sshd` or a fleet binary name) but its real executable is not a root-owned critical binary
- **THEN** the enforcer still terminates it — the critical-process protection is keyed on the trusted executable identity, not the self-reported name

#### Scenario: A pid whose captured identity no longer matches is spared
- **WHEN** a terminate decision targets a live pid but the process start-time captured at observation does not match the current holder's start-time (the pid was reused)
- **THEN** the enforcer does not terminate that process, while a target whose captured start-time matches the live process is terminated
