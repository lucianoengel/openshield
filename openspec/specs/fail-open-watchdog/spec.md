# fail-open-watchdog Specification

## Purpose
The fanotify permission answer: guarantees the kernel is answered within a hard per-event budget regardless of what evaluation does, failing OPEN (FAN_ALLOW) on timeout with a loud high-severity audit, so a slow or crashed pipeline cannot hang a process blocked in TASK_UNINTERRUPTIBLE.
## Requirements
### Requirement: The kernel is answered within a hard deadline regardless of evaluation
For every permission event the responder MUST write a kernel answer within a bounded per-event
deadline, whether or not evaluation has completed. When the deadline elapses first, the answer
MUST be `FAN_ALLOW`.

The process that triggered a permission event is blocked in `TASK_UNINTERRUPTIBLE` until
answered — SIGKILL cannot free it. A responder that waits on an unbounded evaluation hangs the
process and, on a busy path, the machine. Fail-open is the only timeout verdict that does not
trade the host's availability for a verdict that never came (D3).

#### Scenario: A slow evaluation still yields a timely allow
- **WHEN** evaluation is made to exceed the per-event deadline
- **THEN** the responder answers `FAN_ALLOW` within the deadline
- **AND** a test injects the delay and asserts the answer arrives bounded, so a regression that
  waited on evaluation would be caught by the test timing out

#### Scenario: A late result after a timeout does not answer twice
- **WHEN** evaluation completes AFTER the deadline already produced an allow
- **THEN** the late result is discarded and no second answer is written
- **AND** a test asserts exactly one answer per event

### Requirement: Every fail-open is audited high-severity, never silent
A timeout or budget-exceed allow MUST emit a HIGH-severity audit event. It MUST NOT be recorded
as, or be indistinguishable from, an ordinary allow.

A silent fail-open is the worst failure in the system: it converts a Block into an Allow with no
trace, and a rising fail-open rate is the cheapest signal that an adversary is manufacturing
bypasses by making classification slow (D17). The severity and the count are the detection.

#### Scenario: A fail-open produces a distinct high-severity record
- **WHEN** the responder fails open on a timeout
- **THEN** it emits an audit event marked high-severity whose reason identifies it as a fail-open
- **AND** a test asserts both the severity and that it is distinguishable from a normal allow

#### Scenario: A failed audit append surfaces but does not retract the allow
- **WHEN** the audit append for a fail-open fails
- **THEN** the failure surfaces to the caller (a failed append is never silent)
- **AND** the kernel has still been allowed, because the answer precedes and cannot depend on the
  ledger write — the ledger must never be inside the window it records

### Requirement: The agent never waits on its own access
A permission event whose PID is the agent's own MUST be allowed immediately, before any
evaluation.

The agent reads policy and writes the ledger; if its own file access generated a permission event
it then waited on, it would deadlock against itself — and because the block is uninterruptible,
unrecoverably. Self-access is allowed by identity, not by evaluation.

#### Scenario: Self-PID is allowed without evaluation
- **WHEN** a permission event carries the agent's own PID
- **THEN** it is allowed immediately and evaluation is not invoked for it
- **AND** a test asserts the evaluator was never called for a self-PID event

### Requirement: A per-event budget bounds evaluation
Evaluation MUST run under a per-event budget; exceeding it is a timeout-allow, audited
high-severity. A single pathological input MUST NOT be able to consume the responder or hang it.

The classifier bounds bytes and uses a linear-time matcher (D33), but the watchdog's budget is
the outer guarantee that holds even if a future stage ignores those bounds. A decompression bomb
that makes evaluation slow is the canonical case.

#### Scenario: A bomb fixture hits the budget rather than hanging
- **WHEN** an input that makes evaluation exceed the budget is processed
- **THEN** the responder answers allow at the budget boundary and audits it high-severity
- **AND** a test drives this with a deliberately slow evaluation and asserts no hang and the
  audit event

