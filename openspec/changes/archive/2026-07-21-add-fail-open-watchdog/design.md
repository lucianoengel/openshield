## Context

fanotify permission events (`FAN_OPEN_PERM`, class `FAN_CLASS_CONTENT`) require a response
written back to the fd: `FAN_ALLOW` or `FAN_DENY`. Until the response is written, the process
that triggered the event is blocked in `TASK_UNINTERRUPTIBLE` — uninterruptible, so not even
SIGKILL frees it. The spike (`spikes/t005-fanotify`) proved the read/respond mechanics. Nothing
production answers events yet, and the answer path is where a bug becomes a hung host.

The dispatcher already races a stage against `StageDeadline` and reports timeouts as
`SeverityHigh` — but that governs the dispatcher's wait, in-process, after the kernel has been
answered (or not). The watchdog is lower: it owns the kernel answer itself.

## Goals / Non-Goals

**Goals:**
- Guarantee the kernel is answered within a hard deadline for every permission event, regardless
  of what evaluation does.
- On timeout/budget-exceed: `FAN_ALLOW` and a HIGH-severity audit event. Never a silent allow,
  never a hang.
- Self-PID events are allowed immediately, before evaluation — no self-deadlock.
- Test all of this without CAP_SYS_ADMIN by abstracting the kernel edge.

**Non-Goals:**
- Producing BLOCK verdicts (Phase 2). The verdict channel carries them; nothing emits one.
- Stopping an abandoned evaluation goroutine (Go can't preempt it).
- A production-grade fanotify event parser (the adapter is minimal; the spike carries the
  detail).

## Decisions

### The kernel edge is an interface
```go
// PermissionEvent is one FAN_OPEN_PERM event, decoded from the fd.
type PermissionEvent struct {
    PID  int32
    FD   int32      // the kernel's fd for the accessed file; -1 in tests
    Path string     // best-effort, for audit
}

// Responder writes the kernel answer. The real implementation writes a
// fanotify_response to the fanotify fd; the test implementation records it.
type Responder interface {
    Allow(e PermissionEvent) error
    Deny(e PermissionEvent) error
}
```
The watchdog holds a `Responder` and an `Evaluator` (the pipeline behind an interface). All the
logic under test — racing, deadline, self-PID, budget, audit — is pure Go over these two
interfaces. The fanotify fd never appears in a unit test.

### The race, and why FAN_ALLOW wins ties
For each event:
1. If `e.PID == selfPID`, `Allow` immediately and return. Self-access must never wait on
   evaluation; doing so deadlocks the agent against its own ledger write.
2. Start evaluation in a goroutine with a context deadline = the per-event budget.
3. `select` on {evaluation result, deadline}. Deadline first → `Allow` + high-severity audit
   "fail-open: evaluation exceeded budget". Result first → answer per the verdict (Phase 1: the
   verdict is always allow; the mechanism would `Deny` on BLOCK).
4. The response is written exactly once. A late evaluation result after a timeout is discarded —
   the kernel already has its answer, and answering twice is a protocol error.

### Fail-open is the ONLY safe timeout
Failing closed (`Deny` on timeout) would convert a slow classifier into a blocked process and,
with `FAN_OPEN_PERM` on a busy path, a hung machine. For a tool whose first duty is not to take
the host down, the timeout verdict is `Allow`, unconditionally. The safety comes from the
event being LOUD, not from it being blocked.

### Auditing the fail-open goes through the same ledger, off the hot path
The high-severity event is handed to an audit callback (the same `core.Outcome`/severity
vocabulary the dispatcher uses), which appends to the ledger. The append happens after the
kernel is answered — the ledger write must never be inside the window it is recording, or a slow
ledger becomes a hung host. If the audit append fails, that failure surfaces (it is exactly the
"a failed append is never silent" contract), but it does NOT retract the allow already given to
the kernel.

### Budgets
The per-event budget is a wall-clock deadline on evaluation. The classifier already bounds bytes
(worker ceiling) and backtracking (RE2, D33); the watchdog's budget is the outer guarantee that
even if some future stage ignores those, the kernel is still answered. A zip-bomb fixture that
makes evaluation slow must produce a timeout-allow, audited, not a hang — that is the test.

## Risks / Trade-offs

- **The abandoned goroutine leak is real.** A stage that ignores its context runs to completion
  after the watchdog has answered. Bounded per event, and the same limit `pipeline.go` documents.
  A future hard cap (worker process kill) is out of scope.
- **Self-PID bypass is coarse.** It allows ALL of the agent's own access, including, in
  principle, a compromised agent. That is acceptable: an attacker who is the agent has already
  won, and the alternative (the agent waiting on its own file I/O) is a guaranteed deadlock
  versus a hypothetical one.
- **Fail-open is a bypass by construction.** Non-negotiable given the host-availability
  constraint; the design makes it observable rather than pretending it is closed.
- **The privileged fanotify path is thinly tested.** The decision logic is fully tested; the fd
  adapter is small, spike-proven, and behind an optional root-only integration test that skips
  loudly. This is the honest boundary of what CI without privileges can cover.
