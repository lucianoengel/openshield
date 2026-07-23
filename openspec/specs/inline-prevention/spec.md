# inline-prevention Specification

## Purpose
The synchronous tier of two-tier inline prevention: the decision logic that answers a fanotify permission event within its hard budget, turning post-decision containment into true prevention for the cases it can cheaply prove. It plugs into the fail-open watchdog as its evaluator, submits the full-file classification job to the asynchronous engine on every event, and produces an inline block only for a high-confidence bounded partial decision — deferring everything else to asynchronous containment. It never parses content itself; the bounded partial classification runs in the sandboxed worker. The privileged permission-mode syscall adapter and the fd-passing plumbing are external-gated to a host with genuine init-namespace CAP_SYS_ADMIN.

## Requirements

### Requirement: A two-tier prefilter answers the permission window, inline-blocking only high-confidence hits
The synchronous prefilter MUST submit the full-file classification job to the asynchronous
tier on every event, so inline prevention never replaces the complete classification, the
durable audit record, or containment. It MUST answer with an inline block ONLY when a
cheap, bounded partial decision is a deny AND its confidence is at least a configured floor;
a lower-confidence partial deny MUST allow the open and rely on asynchronous containment. A
failure to produce a partial decision MUST fail open, surfacing the error so it is audited,
never blocking the open. The prefilter MUST NOT parse content itself. The partial decision
MUST come from a BOUNDED prefix of the target classified in the sandboxed worker and the
same policy the asynchronous tier runs, and MUST NOT write an audit record.

#### Scenario: A high-confidence partial deny blocks inline while a low-confidence one does not
- **WHEN** the prefilter evaluates a permission event
- **THEN** a high-confidence partial deny yields an inline block, a low-confidence deny or a decide error allows the open, and the full-file job is submitted asynchronously in every case

#### Scenario: A bounded prefix decides synchronously without auditing
- **WHEN** the decider classifies a permission event's target
- **THEN** it reads only a bounded prefix via a no-follow regular-file open, refuses a symlinked target, parses it in the worker, decides via the policy, and returns the decision without writing the ledger

### Requirement: A DENY_EXEC decision inline-blocks an exec

The system SHALL answer an exec-permission event by DENYING the execution to the kernel if and only if
the pipeline decides DENY_EXEC for that exec; every other decision SHALL allow it. The decision path
SHALL remain under the watchdog's hard fail-open budget, so a slow or failing evaluation allows the exec
(inline prevention never becomes a denial of service).

#### Scenario: A denied exec is blocked
- **WHEN** the pipeline decides DENY_EXEC for an exec-permission event
- **THEN** the kernel is answered DENY (the exec is refused inline)

#### Scenario: A permitted exec runs
- **WHEN** the pipeline decides anything other than DENY_EXEC
- **THEN** the kernel is answered ALLOW

#### Scenario: A slow or failing evaluation fails open
- **WHEN** the exec decision exceeds the budget or errors
- **THEN** the kernel is answered ALLOW (fail-open) and the outcome is audited high-severity

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

### Requirement: Application whitelisting refuses a non-approved execution inline

When an execution allowlist is configured, the system SHALL refuse (block) a resolved execution whose
binary is not on the allowlist — default-deny — and SHALL allow an allowlisted execution. The deny-list
and behavioral checks SHALL apply BEFORE the allowlist, so an allowlisted binary that is also deny-listed
or behaviorally suspicious is still blocked (deny takes precedence over allow). An execution whose binary
cannot be identified (its path could not be resolved) SHALL be allowed rather than blocked (availability
over a false block), and the system's own executions SHALL remain exempt so whitelisting cannot deadlock
the agent. When no allowlist is configured, the system SHALL behave as deny-list-only (an unlisted
execution is allowed).

#### Scenario: A non-allowlisted binary is blocked when whitelisting is on
- **WHEN** an allowlist is configured and a process executes a binary that is not on it (path resolved)
- **THEN** the execution is refused inline

#### Scenario: An allowlisted binary runs
- **WHEN** an allowlist is configured and a process executes a binary on it
- **THEN** the execution is allowed (unless it is separately deny-listed or behaviorally suspicious)

#### Scenario: Deny takes precedence over allow
- **WHEN** a binary is on both the allowlist and the deny-list
- **THEN** the execution is refused

#### Scenario: No allowlist means deny-list-only
- **WHEN** no allowlist is configured and a binary is neither deny-listed nor behaviorally suspicious
- **THEN** the execution is allowed
