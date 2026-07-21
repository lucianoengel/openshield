## Context

`privileged.Worker` wraps one worker process; `Classify` serializes with a mutex
because the IPC is a single synchronous framed stream over stdin/stdout. The engine
processes one event at a time, so one worker suffices. The gateway proxy is
concurrent, so it needs parallel classification without changing the worker or the
`classifier` interface both callers depend on.

## Goals / Non-Goals

**Goals:**
- Parallel classification for the concurrent gateway, bounded and with backpressure.
- The pool satisfies the existing `classifier` interface (drop-in for one worker).
- A worker that errors does not poison the pool.

**Non-Goals:**
- Dynamic resizing; health checks beyond replace-on-error; a shared cross-process
  pool. Each process spawns its own.

## Decisions

**A buffered channel of idle workers IS the semaphore.** `Pool.idle` is a channel
holding the currently-idle workers. `Classify` receives one (blocking when all are
busy — natural backpressure — and selecting on `ctx.Done()` so a cancelled request
does not wait forever), uses it, and sends it back. In-flight parses are bounded by
the pool size with no separate lock. Size N → up to N concurrent classifications,
each in its own seccomp/no-network sandbox (D29/D35).

**Replace a worker that errored — its IPC state is unknown.** The framed protocol is
strictly request/response; a timeout (`ErrWorkerTimeout`) leaves a response possibly
still in the pipe (desynchronised), and a crash (`ErrWorkerUnavailable`) leaves a
dead process. Either way the handle is unusable, so on ANY `Classify` error the pool
`Close`s it and spawns a REPLACEMENT (using the stored ctx/path/args), returning the
replacement to the idle set. The error is still returned to the caller (D17: a
worker error is surfaced, never a clean result) — replacement is about pool health,
not swallowing the failure. If the replacement spawn fails, the old (closed) handle
is returned so the slot is not lost; its next use errors and retries replacement,
which avoids permanently shrinking the pool toward deadlock.

**The pool is the gateway's answer, not a change to the engine.** The single
mutex-serialized worker stays correct and is what the endpoint engine uses (one
event at a time). Only the concurrent gateway needs the pool; wiring is a one-line
swap in its binary because the pool satisfies the same interface.

## Risks / Trade-offs

- **Replacement churn under a failing worker binary.** A worker that dies on every
  request causes a spawn per request. Acceptable and self-limiting for a skeleton
  (the failure is surfaced each time); a circuit breaker is a noted follow-up.
- **N processes cost N× the worker's memory.** Bounded by the configured size; the
  operator sizes it. Stated.
- **A checked-out worker is not closed by `Close`.** `Close` drains idle workers;
  in-flight ones exit with the process. Fine for shutdown.
