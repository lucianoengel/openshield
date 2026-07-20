# Spike T-002 — Go GC pause in the fanotify permission window

**Date:** 2026-07-20 · **Decision:** D19 · **Code:** [`../spikes/t002-gc-pause/`](../spikes/t002-gc-pause/)

## Question

D8 chose Go for the whole project. Review challenged that for one component: the fanotify
permission responder. `FAN_OPEN_PERM` blocks the calling process in `TASK_UNINTERRUPTIBLE`
until userspace writes a verdict, so a stalled responder stalls real processes — there are
documented Red Hat and SUSE incidents where a slow fanotify listener hung a machine.

Does Go's garbage collector introduce tail latency large enough to matter there?

## Verdict: **Go stays. GC is not the risk.**

Worst-case response latency across every scenario, including a deliberately hostile one:
**532µs**. Typical is **1-3µs**. A file `open()` delayed by half a millisecond at the extreme
is imperceptible; the failure mode that hangs machines is measured in seconds or is unbounded,
not in hundreds of microseconds.

**The real risk was never the language.** It is the responder stalling for unbounded time —
deadlocking against its own I/O, blocking on IPC to the classifier worker, or crashing without
answering. That is a design problem, and it is already addressed by the fail-open watchdog
(D17/D18, ticket T-011): self-PID bypass, response timeout, auto-`FAN_ALLOW`, safe teardown.
Rewriting this component in Rust would not have removed that risk; it would have removed a
1-3µs GC contribution while leaving the actual hazard untouched.

D19 is closed. D8 stands unmodified.

## Results

Go 1.26.5. Each scenario 8-10s. Latency is producer-hand-off → verdict-produced.
GC pause figures are histogram bucket **upper bounds**, so they overestimate.

**GOMAXPROCS=32** (dev host)

| scenario | ev/s | alloc | p50 | p99 | p99.9 | max | GCs |
|---|---|---|---|---|---|---|---|
| idle | 500 | 0 MB | 962ns | 8.8µs | 21.6µs | 64.7µs | 0 |
| moderate | 500 | 64 MB/s | 1.3µs | 8.2µs | 25.7µs | 58.3µs | 32 |
| heavy | 500 | 256 MB/s | 1.3µs | 9.6µs | 25.6µs | 116.9µs | 34 |
| heavy + 10× events | 5000 | 256 MB/s | 2.9µs | 9.8µs | 24.1µs | **280.8µs** | 34 |

**GOMAXPROCS=2** (constrained endpoint — the case that matters)

| scenario | ev/s | alloc | p50 | p99 | p99.9 | max | GCs |
|---|---|---|---|---|---|---|---|
| idle | 500 | 0 MB | 952ns | 8.2µs | 23.3µs | 102.9µs | 0 |
| moderate | 500 | 64 MB/s | 1.3µs | 8.3µs | 14.2µs | 223.7µs | 26 |
| heavy | 500 | 256 MB/s | 1.3µs | 10.5µs | 21.8µs | 53µs | 26 |
| heavy + 10× events | 5000 | 256 MB/s | 2.8µs | 11µs | 42.7µs | **532.2µs** | 28 |

**GOMAXPROCS=4** — worst case 486.8µs, same shape.

Core count barely moves the result. Even at 2 cores under 256 MB/s allocation and a 5000
event/s rate — well beyond a realistic desktop file-open rate — the tail stays under a
millisecond.

## Methodology, including a mistake worth recording

The first version of this harness produced **incoherent results**: the zero-GC idle scenario
posted the *worst* maximum latency (1.22ms), while the GC-heavy scenario came in lower. That
ordering is impossible if GC is what is being measured.

The cause: latency was measured from the *intended* tick time rather than actual hand-off, so
the harness was measuring `time.Sleep` overshoot (~500µs, dominant) with GC invisible
underneath. Fixed by timestamping at hand-off and moving the responder into its own goroutine
reading from a channel — no sleep in the measured path.

Recorded because the flawed version would have "passed" the ticket's acceptance criterion while
measuring the wrong thing, and because the incoherent ordering is what exposed it. A benchmark
whose results are merely plausible is not evidence.

## Scope

**Measures:** Go-side latency from event hand-off to verdict, under allocation pressure, plus
the runtime's own GC pause distribution.

**Does not measure:** kernel fanotify overhead, syscall cost, or IPC to the classifier worker.
Those are real but they are not the D19 question, and `FAN_CLASS_CONTENT` needs `CAP_SYS_ADMIN`
which the dev sandbox lacks. The narrow question — does the Go runtime itself add dangerous
tail latency — is answerable without them, and is answered.

**What would change the verdict:** if the responder ever does real work per event (parsing,
network, large allocation) the profile changes entirely. It must not — under D13 the privileged
process does bookkeeping only, and content parsing lives in the unprivileged worker.
