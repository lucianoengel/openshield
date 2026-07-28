# inline-prevention

## ADDED Requirements

### Requirement: A file-open permission event MUST be answered from the kernel's descriptor

The privileged agent MUST produce file-open permission events for configured directories and MUST read
any content it needs for a verdict from the descriptor the kernel supplied with the event, never by
re-opening the path.

Re-opening the path raises a further permission event, which the same gate must answer — an
unrecoverable deadlock, because a process inside a permission window is uninterruptible. It is also a
time-of-check-to-time-of-use hole: the path may name a different file by then, and the gate would
authorize what it inspected while releasing what it did not.

#### Scenario: A file open in a monitored directory is decided inline

- **WHEN** a process opens a file in a directory the agent monitors
- **THEN** the open MUST be answered by a verdict, allowed or denied, before it completes

#### Scenario: Answering does not raise a further permission event

- **WHEN** the agent obtains the content it needs to answer
- **THEN** it MUST NOT perform an open that could itself be subject to the gate

### Requirement: The file-open gate MUST fail open

The gate MUST allow the open on every failure to reach a verdict within the budget — the budget elapsing, the deciding process being
unreachable, an IPC error, a classifier failure — and MUST audit each one at high severity.

A file-open gate that failed closed would hang every process on the host, which is a worse outcome
than the disclosure it exists to make harder (D16/D17/D18).

#### Scenario: An unreachable decider allows the open

- **WHEN** the deciding process cannot be reached
- **THEN** the open MUST be allowed
- **AND** the fail-open MUST be audited

### Requirement: The gate MUST refuse to mark a whole mount

The agent MUST refuse a configuration that would place every open on the host through a permission
window.

#### Scenario: A mount-wide scope is refused

- **WHEN** the file-open gate is configured with a mount-wide scope
- **THEN** the agent MUST refuse to start
