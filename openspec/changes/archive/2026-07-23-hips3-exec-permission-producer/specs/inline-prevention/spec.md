## ADDED Requirements

### Requirement: A privileged fanotify producer drives exec-permission decisions on a live kernel

The system SHALL provide a privileged producer that marks exec-permission events on watched paths and,
for each event, decodes it, obtains a verdict from the watchdog, answers the kernel exactly once, and
releases the event's file descriptor. The producer MUST hold no content parser (it runs with elevated
privilege). It MUST be robust: an undecodable, short, or version-mismatched event MUST still answer the
kernel (allowing the execution — fail-open) and MUST NOT leave the executing process blocked, because a
process awaiting a permission answer is parked uninterruptibly. The producer MUST NOT leak file
descriptors across events.

#### Scenario: A watched exec is decided and answered exactly once
- **WHEN** a process executes a binary under a watched path
- **THEN** the producer decodes the exec-permission event, the watchdog decides allow or deny, the kernel is answered once, and the event's descriptor is released

#### Scenario: An undecodable event fails open without hanging
- **WHEN** an event cannot be decoded (a short read or an unexpected version)
- **THEN** the producer answers the kernel to allow the execution and continues, never leaving the executing process parked

### Requirement: A parser-free inline exec decider blocks denied executables

The system SHALL provide an inline exec decider that runs within the permission budget without any
content parser and without inter-process calls, so the privileged producer can decide directly. The
decider SHALL block an execution whose binary is on an operator deny-list (by absolute path or by
basename) or whose exec metadata exceeds a configured behavioral-suspicion threshold, and SHALL allow
every other execution. Because it is the only decider the privileged (parser-free) binary can hold, its
verdict SHALL map to the watchdog's block/allow the same way the pipeline's DENY_EXEC does.

#### Scenario: A deny-listed binary is blocked inline
- **WHEN** a process executes a binary whose path or basename is on the deny-list
- **THEN** the decider returns a block verdict and the kernel refuses the execution

#### Scenario: A permitted binary runs
- **WHEN** a process executes a binary that is neither deny-listed nor behaviorally suspicious
- **THEN** the decider allows it and the execution proceeds

### Requirement: The privileged exec-monitor binary holds no content parser

The privileged binary that runs the exec-permission producer MUST NOT carry any content-parsing or
structured-decoder dependency in its build, so a memory-safety bug in a parser can never execute with the
producer's privilege. When no exec-monitor is configured, the binary MUST exit non-zero rather than run
as a healthy do-nothing agent.

#### Scenario: The privileged binary's dependency graph is parser-free
- **WHEN** the privileged exec-monitor binary is built
- **THEN** its dependency graph contains no content parser or structured-format decoder

#### Scenario: An unconfigured agent does not masquerade as healthy
- **WHEN** the privileged binary starts with no exec-monitor configured
- **THEN** it exits non-zero
