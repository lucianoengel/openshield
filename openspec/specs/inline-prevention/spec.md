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
