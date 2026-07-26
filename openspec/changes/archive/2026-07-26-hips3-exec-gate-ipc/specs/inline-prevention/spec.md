## ADDED Requirements

### Requirement: An inline exec verdict may come from the full pipeline over IPC

The system SHALL provide a transport by which the privileged exec gate obtains a verdict from the
unprivileged engine's pipeline, so an inline exec decision can depend on dynamic policy rather than only
on the static deny-list/whitelist the privileged binary holds. The verdict SHALL block the execution if
and only if the pipeline decides `DENY_EXEC`; every other decision SHALL allow it.

The transport SHALL be opt-in. With it unconfigured, the gate's behavior SHALL be identical to the static
path, and a socket that is absent or unreachable SHALL NOT prevent the privileged agent from starting.

#### Scenario: A policy DENY refuses a real execution
- **WHEN** the engine's policy decides `DENY_EXEC` for an execution and the gate is configured to consult
  it over IPC
- **THEN** the execution is refused by the kernel (the process receives a permission error), proven on a
  real kernel through the live permission path

#### Scenario: A policy ALLOW lets the same execution run
- **WHEN** the same execution is evaluated under a policy that allows it
- **THEN** it runs normally
- **AND** the test FAILS if the implementation ignores the IPC verdict and always allows

### Requirement: The exec-verdict transport carries no parser into the privileged process

The exec-verdict transport SHALL be implemented without any structured-format decoder and without
protobuf, so the privileged binary's dependency graph gains no wire-format parser. Frame lengths SHALL be
validated against a hard bound BEFORE any allocation, so a length prefix from the peer is not an
allocation primitive.

This SHALL be enforced by a build-time check over the privileged binary's dependencies, not by review: the
binary MUST carry no content parser and no protobuf/structured-decoder dependency.

#### Scenario: The privileged binary's dependencies stay clean
- **WHEN** the privileged binary's dependency graph is computed
- **THEN** it contains no content parser and no protobuf or structured-decoder package
- **AND** the check FAILS the build if a future import introduces one

#### Scenario: An oversized length prefix is refused before allocating
- **WHEN** a frame declares a length beyond the hard bound
- **THEN** it is refused as an error without allocating a buffer of that size

### Requirement: The gate never blocks and never guesses a verdict

Every transport failure SHALL be surfaced as an error rather than resolved into a verdict. A response
whose request id does not match the pending request, a truncated frame, an unrecognized magic or version,
and a closed or unreadable socket SHALL each be errors.

The gate SHALL NOT answer one execution with another execution's verdict under any circumstances —
answering event A with event B's verdict is the worst available failure of an inline gate, because it is
both wrong and invisible.

Socket deadlines SHALL be shorter than the permission budget, so the transport cannot be the thing that
exhausts the window.

#### Scenario: A mismatched response is an error, not a verdict
- **WHEN** the engine returns a response carrying a different request id than the one asked
- **THEN** the client returns an error (and the watchdog fails open with a loud audit) rather than
  applying that verdict
- **AND** the test FAILS if the implementation accepts a mismatched id

#### Scenario: A malformed or truncated response is an error
- **WHEN** a response has a bad magic, an unknown version, or is truncated
- **THEN** the client returns an error and no verdict is inferred

### Requirement: A dead, hung or overwhelmed engine must never wedge execution

On IPC timeout, connection failure, engine crash, or in-flight overflow, the gate SHALL ALLOW the
execution and record a high-severity audit event. It SHALL NOT fail closed, and it SHALL NOT hang.

**Fail-open here is a load-bearing safety property, not a bug.** A privileged gate that fails closed when
its evaluator dies removes a machine's ability to run programs — the same discipline as the network bypass
watchdog and the egress fail-open (D17/D73). A test asserting fail-open MUST therefore FAIL if the
implementation is changed to fail closed.

The gate SHALL survive an engine restart: a later execution is evaluated normally after reconnecting,
with no stuck error state and no stuck denial.

#### Scenario: A hung engine allows the exec within the budget
- **WHEN** the engine does not answer within the budget
- **THEN** the execution is allowed and a high-severity fail-open is audited
- **AND** the test FAILS if the gate is changed to fail closed on timeout

#### Scenario: A killed engine does not leave the gate stuck
- **WHEN** the engine is killed and later restarted
- **THEN** executions during the outage are allowed with audit, and an execution after the restart is
  evaluated normally again

### Requirement: A fork storm cannot amplify into an IPC storm

The gate SHALL bound the load a rapid succession of executions can place on the transport: a repeated
execution of the same binary MAY be answered from a short-lived cached verdict, and after a threshold of
consecutive failures for a path the gate SHALL fail open WITHOUT attempting further calls until a cooldown
elapses. In-flight requests SHALL be bounded, and overflow SHALL fail open immediately rather than queue.

#### Scenario: Consecutive failures trip the breaker
- **WHEN** a path's evaluation fails repeatedly past the threshold
- **THEN** subsequent executions of that path fail open without an IPC attempt, until the cooldown expires
- **AND** the test FAILS if the breaker is removed

#### Scenario: A repeated exec is answered from the cached verdict
- **WHEN** the same binary is executed again within the cache TTL
- **THEN** the cached verdict answers it without a new pipeline evaluation
