# enforcement delta

## ADDED Requirements

### Requirement: The process enforcers carry out kill and deny-exec, fail-safe
The enforcement layer MUST carry out KILL_PROCESS by terminating the target process by pid,
and MUST REFUSE to act on pid ≤ 1 (the kernel and init), on its own process, or on a
non-numeric target. It MUST carry out DENY_EXEC by recording a deny for an exec handle
through a controller the permission handler applies, and MUST error when there is no
controller or no target rather than silently allowing the execution. Both MUST use the
existing targeted-enforcer interface, receiving only the verdict in the Decision.

#### Scenario: A kill terminates the target but refuses dangerous pids
- **WHEN** the kill enforcer is asked to enforce KILL_PROCESS on a pid
- **THEN** a normal target process is terminated, while pid ≤ 1, the enforcer's own pid, and a non-numeric target are refused; and a deny with no controller errors rather than allowing the execution
