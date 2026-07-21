## ADDED Requirements

### Requirement: The worker cannot open a network socket
The unprivileged worker MUST install a seccomp filter that denies network syscalls, and MUST do
so before it reads any attacker-controlled input. After the filter is applied, an attempt to
create a socket MUST fail.

A parser RCE is the threat the privilege split exists for (D13; ClamAV CVE-2025-20260). The split
stops it becoming host root; denying the network stops it becoming exfiltration or a reverse
shell. A worker that cannot call `socket` cannot phone home no matter what the parser bug lets an
attacker run. The filter must be in force before the first byte is read, or a fast exploit races
it.

#### Scenario: Socket creation fails after the sandbox is applied
- **WHEN** the sandbox is applied and the process then attempts to create a socket
- **THEN** the attempt fails with a permission error
- **AND** a test asserts the failure, so a regression that dropped or weakened the filter is caught

#### Scenario: The filter covers all runtime threads
- **WHEN** a socket is attempted from a goroutine that may run on a different OS thread than the
  one that applied the filter
- **THEN** it still fails
- **AND** a test spawns such a goroutine, because a thread-local filter would leave the sandbox
  trivially bypassable

### Requirement: An absent sandbox is loud, never silent
On a platform where the sandbox cannot be applied, the worker MUST report that it was not applied,
rather than proceeding as though it had been.

Only Linux ships (D9), but a developer building on another platform must not mistake an
unsandboxed run for a sandboxed one. A silently absent protection is worse than an obviously
absent one: it manufactures false confidence.

#### Scenario: Non-Linux reports the sandbox is absent
- **WHEN** sandbox application is attempted on a platform without seccomp support
- **THEN** it returns a distinct "unsupported" signal the caller surfaces prominently
- **AND** it does not return success

### Requirement: A decompression bomb is rejected before it is parsed
When the worker decompresses input, expansion MUST be bounded by ratio, absolute output size, and
nesting depth, and an input exceeding any bound MUST be rejected before the over-limit bytes reach
a parser or memory.

The raw byte ceiling bounds a large file; it does not bound a small file that expands hugely. A
decompression bomb is caught by expansion limits, and it must be caught at the guard, not by the
process running out of memory (D13).

#### Scenario: An over-ratio expansion is stopped at the guard
- **WHEN** decompressing input would exceed the expansion ratio or absolute size cap
- **THEN** the guard returns an error at the moment the bound is crossed
- **AND** the caller does not receive the over-limit bytes
- **AND** a test drives a high-ratio expansion and asserts the error rather than an OOM

#### Scenario: Excessive nesting is stopped
- **WHEN** nested archives exceed the depth cap
- **THEN** the guard rejects the input rather than recursing further
