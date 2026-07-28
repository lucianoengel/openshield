

## Purpose

Refusing an exec before it happens: a privileged, parser-free gate that answers the kernel's permission
window, backed by a two-tier prefilter for high-confidence local denials and by the full pipeline over
IPC for everything else. The controlling rule is that it NEVER guesses a verdict and never wedges the
host — a dead, hung or overwhelmed engine fails OPEN and says so, and a fork storm cannot amplify into
an IPC storm. A coordinated-response intent can drive a denial, and any containment it causes is
liftable.

## Requirements

### Requirement: An inline exec verdict may be driven by a coordinated-response intent

The system SHALL make the coordinated-response intent in effect for an execution's subject available to the
inline exec decision as typed policy CONTEXT, so a policy can refuse a contained entity's execution INLINE
rather than terminating the process after it has run.

The intent SHALL be delivered as context a policy consults, never as an instruction the gate executes. A
policy that does not read it SHALL be unaffected by any intent.

That property has an honest cost which SHALL NOT be described away: a deployment running a policy that never
reads the intent provides NO containment at the exec gate and reports nothing unusual.

#### Scenario: A contained entity's execution is refused inline
- **WHEN** a containment intent is in effect for an execution's subject and the policy reads it
- **THEN** the execution is refused by the kernel before the process runs

#### Scenario: A policy that ignores intents is unaffected
- **WHEN** a containment intent is in effect and the policy does not read it
- **THEN** the execution proceeds exactly as it would with no intent

### Requirement: The intent reaches policy as a closed value, never free text

The intent SHALL be exposed to policy as a member of the CLOSED response-intent vocabulary, together with a
flag distinguishing "no intent" from "an intent that says nothing". It SHALL NOT be carried as free text.

The enrichment context is deliberately a closed typed set rather than an open map, so that a compromised
control plane cannot influence decisions by inventing keys a policy happens to read; a free-text intent
would reopen exactly that door.

#### Scenario: The intent is a closed vocabulary member
- **WHEN** policy input is built for an execution whose subject has an intent
- **THEN** the intent appears as a closed-vocabulary value and a presence flag, and nothing free-form

### Requirement: A containment is liftable

The system SHALL allow an execution that was refused under containment to run again once no intent is in
effect for its subject — because none was issued, or because the intent expired.

A containment that could not be lifted would be a permanent quarantine.

#### Scenario: Lifting the containment restores execution
- **WHEN** the containment for a subject is no longer in effect
- **THEN** the same executable runs successfully

### Requirement: Intent consumption does not change the gate's fail-open rule

Consuming intents SHALL NOT alter the exec gate's behaviour when its evaluator is unavailable: a timeout,
crash or unreachable engine still ALLOWS the execution with a high-severity audit.

Containment therefore depends on a live engine, and that dependency SHALL be stated rather than implied
away.

#### Scenario: A dead engine still allows execution
- **WHEN** the engine is unavailable while a containment is nominally in effect
- **THEN** the execution is allowed and the fail-open is audited

### Requirement: The exec-verdict socket is reachable through configuration

The engine SHALL serve exec verdicts on the configured socket, answering BLOCK exactly when the pipeline
decides DENY_EXEC and ALLOW otherwise. Because the engine CREATES that socket and the privileged gate
merely connects to it, neither side's configuration SHALL require the socket to exist at startup —
requiring it makes the serving side unbootable and makes the gate, whose contract is to fail OPEN when
the engine is unreachable, fail CLOSED before it has run.

When the engine is unreachable the gate SHALL answer ALLOW and SHALL report why, so the fail-open is
auditable rather than indistinguishable from a permitted execution.

#### Scenario: A denied binary is refused over the socket
- **WHEN** the gate asks the running engine about a path the policy denies
- **THEN** the answer is BLOCK

#### Scenario: A permitted binary is allowed over the socket
- **WHEN** the gate asks about a path the policy permits
- **THEN** the answer is ALLOW

#### Scenario: A stopped engine yields a reported fail-open
- **WHEN** the engine is stopped and the gate asks about a path the policy denies
- **THEN** the answer is ALLOW and an error describing the failure accompanies it

### Requirement: A two-tier prefilter answers the permission window, inline-blocking only high-confidence hits
The synchronous prefilter MUST submit the full-file classification job to the asynchronous
tier on every event, so inline prevention never replaces the complete classification, the
durable audit record, or containment. It MUST answer with an inline block ONLY when a
cheap, bounded partial decision is a deny AND its confidence is at least a configured floor;
a lower-confidence partial deny MUST allow the open and rely on asynchronous containment. A
failure to produce a partial decision MUST fail open, surfacing the error so it is audited,
never blocking the open. The prefilter MUST NOT parse content itself. The partial decision
MUST come from a BOUNDED prefix of the target classified in the sandboxed worker and the
same policy the asynchronous tier runs, and MUST NOT write an audit record. The prefix read
MUST use a no-follow, regular-file-only open, refusing a symlinked or special-file target.

#### Scenario: A high-confidence partial deny blocks inline while a low-confidence one does not
- **WHEN** the prefilter evaluates a permission event
- **THEN** a high-confidence partial deny yields an inline block, a low-confidence deny or a decide error allows the open, and the full-file job is submitted asynchronously in every case

#### Scenario: A bounded prefix decides synchronously without auditing
- **WHEN** the decider classifies a permission event's target
- **THEN** it reads only a bounded prefix via a no-follow regular-file open, refuses a symlinked target, parses it in the worker, decides via the policy, and returns the decision without writing the ledger

<!-- restored from 2026-07-21-sec7-prefilter-nofollow -->

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

<!-- restored from 2026-07-23-hips3-deny-exec-inline -->

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

<!-- restored from 2026-07-23-hips3-exec-permission-producer -->

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

<!-- restored from 2026-07-23-hips3-exec-permission-producer -->

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

<!-- restored from 2026-07-23-hips3-exec-permission-producer -->

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

<!-- restored from 2026-07-23-hips4-app-whitelisting -->

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

<!-- restored from 2026-07-26-hips3-exec-gate-ipc -->

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

<!-- restored from 2026-07-26-hips3-exec-gate-ipc -->

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

<!-- restored from 2026-07-26-hips3-exec-gate-ipc -->

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

<!-- restored from 2026-07-26-hips3-exec-gate-ipc -->

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

<!-- restored from 2026-07-26-hips3-exec-gate-ipc -->
